"""Opt-in observation transport for this lab, not a production Relay implementation.

Reports remain opaque original JSON here. The production Manager validates them before
putting them in its source-bound NetworkObservationStore. A 200 only acknowledges transport.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import uuid

MAX_BODY = 128 * 1024
MAX_RECORDS = 1024
OPERATOR = 'hp-manager'


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate observation JSON key')
        value[key] = item
    return value


def decode_body(raw):
    if not raw or len(raw) > MAX_BODY:
        raise ValueError('observation body bound')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=no_duplicates,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-JSON number')))
    if not isinstance(value, dict) or set(value) != {'host', 'report'} or value['host'] != 'gateway' or not isinstance(value['report'], dict):
        raise ValueError('fixed observation host/envelope required')
    return value


def certificate_cn(connection):
    names = [value for group in connection.getpeercert().get('subject', ())
             for name, value in group if name == 'commonName']
    return names[0] if len(names) == 1 else None


class ObservationTransport:
    def __init__(self, base):
        self.root = Path(base) / 'observation-transport'
        try:
            self.root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = self.root.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
            raise ValueError('protected observation transport directory required')
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parent = os.open(self.root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(self.fd)
            os.fsync(parent)
        finally:
            os.close(parent)
        self.lock = threading.Lock()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def check_root(self):
        held, linked = os.fstat(self.fd), self.root.lstat()
        if not stat.S_ISDIR(linked.st_mode) or (held.st_dev, held.st_ino) != (linked.st_dev, linked.st_ino) or linked.st_uid != os.geteuid() or stat.S_IMODE(linked.st_mode) != 0o700:
            raise ValueError('observation directory replaced')

    def read(self, name, maximum, durable=False):
        self.check_root()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 or before.st_size > maximum:
                raise ValueError('unsafe observation record')
            chunks = []
            remaining = maximum + 1
            while remaining:
                block = os.read(fd, min(65536, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b''.join(chunks)
            after = os.fstat(fd)
            linked = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) or getattr(before, key) != getattr(linked, key) for key in fields):
                raise ValueError('observation record changed')
            if durable:
                os.fsync(fd)
                synced, path_after_sync = os.fstat(fd), os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if any(getattr(before, key) != getattr(synced, key) or getattr(before, key) != getattr(path_after_sync, key) for key in fields):
                    raise ValueError('observation record changed during durability barrier')
                self.check_root()
            return raw
        finally:
            os.close(fd)

    def exclusive(self, name, raw):
        self.check_root()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError('short observation write')
                view = view[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self.fd)
        self.check_root()

    def record(self, digest, durable=False):
        if not re.fullmatch('[a-f0-9]{64}', digest):
            raise ValueError('invalid observation record reference')
        body = self.read('body-' + digest + '.bin', MAX_BODY, durable=durable)
        if hashlib.sha256(body).hexdigest() != digest:
            raise ValueError('observation original hash mismatch')
        decode_body(body)
        receipt = json.loads(self.read('receipt-' + digest + '.json', 1024, durable=durable))
        if set(receipt) != {'bodySha256', 'receivedAt'} or receipt['bodySha256'] != digest or not isinstance(receipt['receivedAt'], str):
            raise ValueError('invalid observation receipt')
        datetime.datetime.strptime(receipt['receivedAt'], '%Y-%m-%dT%H:%M:%S.%fZ')
        if durable:
            os.fsync(self.fd)
            self.check_root()
        return body, receipt

    def put(self, body):
        decode_body(body)
        digest = hashlib.sha256(body).hexdigest()
        with self.lock:
            if any(name.startswith('.current-') for name in os.listdir(self.fd)):
                raise ValueError('partial observation pointer requires explicit diagnosis')
            try:
                # Visible complete files can remain after an earlier fsync error.
                # Re-establish both held-file barriers and the directory barrier
                # before returning their original receipt; never infer durability.
                original, receipt = self.record(digest, durable=True)
                if original != body:
                    raise ValueError('observation original differs')
            except FileNotFoundError:
                # A partial existing write is never adopted or repaired. exclusive()
                # refuses it, and its original evidence remains for diagnosis.
                for name in ('body-' + digest + '.bin', 'receipt-' + digest + '.json'):
                    try:
                        os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ValueError('partial observation record requires explicit diagnosis')
                if len([name for name in os.listdir(self.fd) if name.startswith('body-')]) >= MAX_RECORDS:
                    raise ValueError('observation transport full; explicit archival required')
                received = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
                receipt = {'bodySha256': digest, 'receivedAt': received}
                self.exclusive('body-' + digest + '.bin', body)
                self.exclusive('receipt-' + digest + '.json', json.dumps(receipt).encode())
            name = '.current-' + uuid.uuid4().hex
            self.exclusive(name, json.dumps({'bodySha256': digest}).encode())
            os.replace(name, 'current.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
            os.fsync(self.fd)
            return receipt

    def get(self):
        with self.lock:
            try:
                current = json.loads(self.read('current.json', 1024))
            except FileNotFoundError:
                return b'{"observations":[]}'
            if set(current) != {'bodySha256'}:
                raise ValueError('invalid observation pointer')
            body, receipt = self.record(current['bodySha256'])
            # Only add the actual receiver receipt. Original report tokens, including
            # numeric spelling and timestamps, are copied verbatim, never normalized.
            record = body.rstrip()[:-1] + b',"receivedAt":' + json.dumps(receipt['receivedAt']).encode() + b'}'
            return b'{"observations":[' + record + b']}'


def handle_observation(handler, transport):
    if not handler.path.startswith('/network/observations'):
        return False
    status, raw = 404, b'{"error":"unknown observation path"}'
    if handler.path == '/network/observations':
        who = certificate_cn(handler.connection)
        if handler.command == 'GET':
            if who != OPERATOR:
                status, raw = 403, b'{"error":"service observation reader required"}'
            else:
                try:
                    raw, status = transport.get(), 200
                except (OSError, ValueError, RecursionError):
                    status, raw = 503, b'{"error":"observation transport unavailable"}'
        elif handler.command == 'POST':
            if who != 'gateway':
                status, raw = 403, b'{"error":"fixed gateway identity required"}'
            else:
                lengths = handler.headers.get_all('Content-Length', [])
                if handler.headers.get('Transfer-Encoding') is not None or len(lengths) != 1 or not re.fullmatch('[0-9]{1,9}', lengths[0]):
                    status, raw = 400, b'{"error":"bounded content length required"}'
                elif not 0 < int(lengths[0]) <= MAX_BODY:
                    status, raw = 413, b'{"error":"observation body too large"}'
                else:
                    try:
                        handler.connection.settimeout(5)
                        body = handler.rfile.read(int(lengths[0]))
                        if len(body) != int(lengths[0]):
                            raise ValueError('incomplete observation body')
                        decode_body(body)
                    except (OSError, ValueError, UnicodeError, RecursionError):
                        status, raw = 400, b'{"error":"invalid observation envelope"}'
                    else:
                        try:
                            receipt = transport.put(body)
                            status, raw = 200, json.dumps({'receivedAt': receipt['receivedAt'], 'transportReceiptOnly': True}).encode()
                        except (OSError, ValueError, RecursionError):
                            status, raw = 503, b'{"error":"observation transport unavailable"}'
        else:
            status, raw = 405, b'{"error":"method not allowed"}'
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json')
    handler.send_header('Content-Length', str(len(raw)))
    # Errors may leave unread request bytes; do not parse another request on it.
    handler.send_header('Connection', 'close')
    handler.end_headers()
    handler.wfile.write(raw)
    handler.close_connection = True
    return True
