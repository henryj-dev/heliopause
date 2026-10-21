"""Protected NetworkManager keyfile primitives for the bounded persistence backend.

No caller-controlled path or shell command. A profile never autoconnects: boot activation
requires the owning Executor's independently confirmed journal entry.
"""
import hashlib
import os
import re
import stat
import ctypes
import uuid

DRIVER = 'networkmanager-wireguard-1.56-v1'
BOOT_POLICY = 'agent-confirmed-only'
DIRECTORY = '/etc/NetworkManager/system-connections'


def profile_uuid(transaction):
    if not isinstance(transaction, str) or not re.fullmatch(r'[a-f0-9]{32}', transaction):
        raise ValueError('invalid profile transaction identity')
    return str(uuid.UUID(hex=transaction))


def render(operation, owner, private_key):
    # All interpolation is validated here as well as at the signed operation boundary.
    # Import lazily so the Executor can select the backend without a circular import.
    from network_executor import validate_operation, key
    validate_operation(operation)
    if operation['driver'] != DRIVER or operation['bootPolicy'] != BOOT_POLICY:
        raise ValueError('unsupported persistent profile contract')
    if not re.fullmatch(r'heliopause:[a-f0-9]{32}:[a-f0-9]{32}', owner):
        raise ValueError('invalid profile owner')
    transaction = owner.split(':')[1]
    if operation['profileUuid'] != profile_uuid(transaction) or operation['interfaceName'] != 'hp'+transaction[:12]:
        raise ValueError('profile identity must bind transaction')
    if not key(private_key):
        raise ValueError('invalid profile secret')
    lines = ['[connection]', 'id=heliopause-'+operation['profileUuid'],
             'uuid='+operation['profileUuid'], 'type=wireguard',
             'interface-name='+operation['interfaceName'], 'autoconnect=false',
             '[wireguard]', 'private-key='+private_key, 'private-key-flags=0',
             'listen-port='+str(operation['listenPort']), 'mtu='+str(operation['mtu']),
             'peer-routes=false', 'ip4-auto-default-route=0', 'ip6-auto-default-route=0']
    for peer in operation['peers']:
        lines += ['[wireguard-peer.'+peer['publicKey']+']', 'endpoint='+peer['endpoint'],
                  'allowed-ips='+';'.join(peer['allowedIps'])+';', 'persistent-keepalive=1']
    lines += ['[ipv4]', 'method=manual', 'address1='+operation['address'],
              'never-default=true', 'ignore-auto-routes=true', 'ignore-auto-dns=true']
    lines += ['route'+str(i)+'='+route+',,42760' for i, route in enumerate(operation['routes'], 1)]
    lines += ['[ipv6]', 'method=disabled', '[user]', 'heliopause.owner='+owner]
    return ('\n'.join(lines)+'\n').encode('ascii')


class ProfileStore:
    """Filesystem boundary only; injected directories are for isolated tests, never approvals."""
    def __init__(self, directory=DIRECTORY):
        self.directory = directory

    def directory_fd(self):
        # Refuse symlinks in every parent, not just the final keyfile. The production path
        # is fixed; restrictive protected parents prevent a non-root writer replacing it.
        path = os.path.abspath(self.directory)
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.split('/')[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022:
                    raise ValueError('unsafe persistent profile directory')
            return fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def basename(identity):
        if not isinstance(identity, str) or str(uuid.UUID(identity)) != identity:
            raise ValueError('invalid profile UUID')
        return 'heliopause-'+identity+'.nmconnection'

    def read(self, identity):
        return self._read_name(self.basename(identity))

    def _read_name(self, basename):
        directory = self.directory_fd()
        try:
            fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 32768:
                    raise ValueError('unsafe persistent profile file')
                value = os.read(fd, 32769)
                if len(value) > 32768:
                    raise ValueError('persistent profile exceeds bound')
                return value
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    @staticmethod
    def staging_name(identity, owner):
        ProfileStore.basename(identity)
        if not re.fullmatch(r'heliopause:[a-f0-9]{32}:[a-f0-9]{32}', owner):
            raise ValueError('invalid staging owner')
        return '.heliopause-'+identity+'-'+owner.split(':')[2]

    def barrier(self):
        directory = self.directory_fd()
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def remove_staging(self, identity, owner, expected_hash):
        name = self.staging_name(identity, owner)
        try:
            content = self._read_name(name)
        except FileNotFoundError:
            self.barrier()
            return
        if hashlib.sha256(content).hexdigest() != expected_hash:
            # A partial write is preserved as explicit recovery debt, never a successful undo.
            raise ValueError('staging secret incomplete or ownership conflict')
        directory = self.directory_fd()
        try:
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)

    def create(self, identity, content, owner):
        if not isinstance(content, bytes) or not 1 <= len(content) <= 32768:
            raise ValueError('invalid persistent profile size')
        directory = self.directory_fd()
        temporary = self.staging_name(identity, owner)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                # Linux RENAME_NOREPLACE publishes one link atomically. Hardlink+unlink
                # would leave a two-link keyfile if power failed between those writes.
                rename = ctypes.CDLL(None, use_errno=True).renameat2
                rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
                rename.restype = ctypes.c_int
                if rename(directory, temporary.encode(), directory, self.basename(identity).encode(), 1):
                    code = ctypes.get_errno()
                    raise OSError(code, os.strerror(code))
            finally:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
                os.fsync(directory)
        finally:
            os.close(directory)

    def remove(self, identity, expected_hash):
        # This primitive does not remove NM's loaded connection or the kernel device.
        # The owning driver must check those stores before calling it.
        try:
            content = self.read(identity)
        except FileNotFoundError:
            self.barrier()
            return
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise ValueError('persistent profile ownership conflict')
        directory = self.directory_fd()
        try:
            os.unlink(self.basename(identity), dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(directory)
