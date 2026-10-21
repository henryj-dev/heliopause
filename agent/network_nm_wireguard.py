"""Bounded NM 1.56 keyfile driver; used only through the production Executor writer."""
import hashlib
import os
import re
import sys
from network_executor import LinuxWireGuard
from network_nm_profile import DRIVER, ProfileStore, render


class NetworkManagerWireGuard(LinuxWireGuard):
    identity = DRIVER

    def __init__(self, secrets):
        super().__init__(secrets)
        self.store = ProfileStore()
        self.row = None

    def bind(self, row):
        self.row = row

    def available(self):
        if not re.fullmatch(r'nmcli tool, version 1\.56\.0(?:-[A-Za-z0-9_.+]+)?', self.run(['nmcli', '--version'])):
            raise ValueError('unsupported NetworkManager version')
        if self.run(['nmcli', '-g', 'RUNNING', 'general']) != 'running':
            raise ValueError('NetworkManager unavailable')
        fd = self.store.directory_fd()
        os.close(fd)
        helper = os.path.join(os.path.dirname(__file__), 'network_nm_settings.py')
        if self.run([sys.executable, helper, '--probe']) != DRIVER:
            raise ValueError('NetworkManager libnm capability unavailable')

    def profiles(self):
        rows = self.run(['nmcli', '-t', '-f', 'UUID,DBUS-PATH', 'connection', 'show']).splitlines()
        if len(rows) > 128:
            raise ValueError('NetworkManager profile inventory exceeds bound')
        result = {}
        for row in rows:
            identity, path = row.split(':', 1)
            if not re.fullmatch(r'[a-f0-9-]{36}', identity) or not re.fullmatch(r'/org/freedesktop/NetworkManager/Settings/[0-9]+', path):
                raise ValueError('unsupported NetworkManager profile identity')
            if identity in result:
                raise ValueError('duplicate NetworkManager profile UUID')
            result[identity] = path
        return result

    def preflight(self, op, protected):
        self.available()
        profiles = self.profiles()
        if op['profileUuid'] in profiles:
            raise ValueError('existing persistent profile refused')
        try:
            self.store.read(op['profileUuid'])
        except FileNotFoundError:
            pass
        else:
            raise ValueError('existing persistent profile refused')
        for identity in profiles:
            if self.run(['nmcli', '-g', 'connection.interface-name', 'connection', 'show', 'uuid', identity]) == op['interfaceName']:
                raise ValueError('foreign interface profile refused')
        return super().preflight(op, protected)

    def prepare(self, row):
        op = row['authorization']['operation']
        fd = self.secret(op)
        try:
            secret = os.read(fd, 129).strip().decode('ascii')
        finally:
            os.close(fd)
        content = render(op, row['owner'], secret)
        return {'profileHash': hashlib.sha256(content).hexdigest(), 'profileUuid': op['profileUuid'],
                'stagingName': self.store.staging_name(op['profileUuid'], row['owner'])}

    def check_file(self, op, owner):
        if not self.row or self.row.get('owner') != owner or self.row.get('persistence', {}).get('profileUuid') != op['profileUuid']:
            raise ValueError('persistent recovery binding missing')
        expected = self.row['persistence'].get('profileHash')
        if not isinstance(expected, str) or not re.fullmatch(r'[a-f0-9]{64}', expected):
            raise ValueError('persistent recovery commitment missing')
        content = self.store.read(op['profileUuid'])
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError('persistent profile ownership conflict')
        return content

    def cached(self, op):
        path = self.profiles().get(op['profileUuid'])
        if path is None:
            return False
        base = ['busctl', 'get-property', 'org.freedesktop.NetworkManager', path,
                'org.freedesktop.NetworkManager.Settings.Connection']
        if self.run(base+['Unsaved']) != 'b false':
            raise ValueError('unsaved or foreign persistent profile')
        expected = os.path.join(self.store.directory, self.store.basename(op['profileUuid']))
        # busctl encodes a string as JSON-compatible quoted text; paths here are fixed ASCII.
        if self.run(base+['Filename']) != 's "'+expected+'"':
            raise ValueError('persistent profile source conflict')
        if self.row is None:
            raise ValueError('persistent profile authority missing')
        content = self.check_file(op, self.row['owner'])
        helper = os.path.join(os.path.dirname(__file__), 'network_nm_settings.py')
        if self.run([sys.executable, helper, op['profileUuid'], expected], content) != 'matching':
            raise ValueError('loaded persistent artifact mismatch')
        return True

    def create(self, op, owner):
        # Executor has already persisted the profile hash and owner before this call.
        if self.prepare(self.row) != self.row.get('persistence'):
            raise ValueError('secret or persistent commitment changed')
        fd = self.secret(op)
        try:
            content = render(op, owner, os.read(fd, 129).strip().decode('ascii'))
        finally:
            os.close(fd)
        if hashlib.sha256(content).hexdigest() != self.row['persistence']['profileHash']:
            raise ValueError('persistent commitment changed')
        self.store.create(op['profileUuid'], content, owner)

    def configure(self, op):
        self.check_file(op, self.row['owner'])
        path = os.path.join(self.store.directory, self.store.basename(op['profileUuid']))
        if not self.cached(op):
            self.run(['nmcli', '--wait', '10', 'connection', 'load', path])
        if not self.cached(op):
            raise ValueError('persistent profile load unverified')
        self.run(['nmcli', '--wait', '10', 'connection', 'up', 'uuid', op['profileUuid']])
        self.check_file(op, self.row['owner'])

    def routes(self, op):
        # NM activates the exact approved addresses/routes together with the connection.
        # Independent verification and local shape checks remain mandatory before confirm.
        pass

    def ownership_marker(self, link, op, owner):
        self.check_file(op, owner)
        if not self.cached(op):
            raise ValueError('persistent profile cache missing')
        active = self.run(['nmcli', '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active']).splitlines()
        if op['profileUuid']+':'+op['interfaceName'] not in active:
            raise ValueError('persistent active device binding missing')
        alias = link.get('ifalias', link.get('alias'))
        if alias not in {None, owner} or link.get('group') not in {None, 0, '0', 'default'}:
            raise ValueError('persistent device ownership conflict')
        if link.get('linkinfo', {}).get('info_kind') != 'wireguard':
            raise ValueError('persistent device kind conflict')
        # Unlike the kernel driver, NM supplies the active UUID/device ownership marker.
        # Remaining kernel shape checks are shared with LinuxWireGuard.owned().
        return owner

    def remove(self, op, owner):
        self.available()
        links = self.ip('-d', 'link', 'show')
        present = any(link['ifname'] == op['interfaceName'] for link in links)
        self.store.remove_staging(op['profileUuid'], owner, self.row['persistence']['profileHash'])
        try:
            self.check_file(op, owner)
        except FileNotFoundError:
            if present or op['profileUuid'] in self.profiles():
                raise ValueError('persistent profile missing with remaining objects')
            self.store.barrier()
            return
        cached = self.cached(op)
        if present and not self.owned(op, owner):
            raise ValueError('persistent interface ownership unavailable')
        if cached:
            self.run(['nmcli', '--wait', '10', 'connection', 'delete', 'uuid', op['profileUuid']])
        self.store.remove(op['profileUuid'], self.row['persistence']['profileHash'])
        if op['profileUuid'] in self.profiles() or any(link['ifname'] == op['interfaceName'] for link in self.ip('-d', 'link', 'show')):
            raise ValueError('persistent rollback removal unverified')
        try:
            self.store.read(op['profileUuid'])
        except FileNotFoundError:
            return
        raise ValueError('persistent rollback file removal unverified')

    def verify_presence(self, op, owner):
        self.configuration_matches(op, owner)

    def configuration_matches(self, op, owner):
        if not self.owned(op, owner):
            raise ValueError('persistent interface missing')
        link = self.ip('-d', 'link', 'show', 'dev', op['interfaceName'])[0]
        if 'UP' not in link.get('flags', []) or self.run(['nmcli', '-g', 'GENERAL.STATE', 'connection', 'show', 'uuid', op['profileUuid']]) != 'activated':
            raise ValueError('persistent activation incomplete')
        if self.run(['wg', 'show', op['interfaceName'], 'fwmark']) != 'off':
            raise ValueError('persistent fwmark mismatch')
        keepalive = dict(line.split() for line in self.run(['wg', 'show', op['interfaceName'], 'persistent-keepalive']).splitlines())
        if keepalive != {peer['publicKey']:'1' for peer in op['peers']}:
            raise ValueError('persistent keepalive mismatch')
        fingerprint = self.fingerprint(op)
        if (fingerprint['publicKey'] != op['publicKey'] or fingerprint['listenPort'] != str(op['listenPort']) or
                fingerprint['addresses'] != [op['address']] or
                set(fingerprint['peers'].split()) != {peer['publicKey'] for peer in op['peers']}):
            raise ValueError('persistent kernel shape mismatch')
        for destination in op['routes']:
            if self.route_get(destination.split('/')[0])['dev'] != op['interfaceName']:
                raise ValueError('persistent route mismatch')

    def manager_instance(self):
        value = self.run(['busctl', 'call', 'org.freedesktop.DBus', '/org/freedesktop/DBus',
                          'org.freedesktop.DBus', 'GetNameOwner', 's', 'org.freedesktop.NetworkManager'])
        if not re.fullmatch(r's ":[0-9]+\.[0-9]+"', value):
            raise ValueError('NetworkManager owner unavailable')
        return value

    def prepare_restore(self, row, protected):
        op = row['authorization']['operation']
        self.bind(row)
        self.available()
        # A cached key is insufficient: the protected original secret must still be valid.
        if self.prepare(row) != row['persistence']:
            raise ValueError('persistent restoration material mismatch')
        self.check_file(op, row['owner'])
        # An inactive foreign profile can also claim the approved device name later.
        for identity in self.profiles():
            if identity != op['profileUuid'] and self.run(['nmcli', '-g', 'connection.interface-name', 'connection', 'show', 'uuid', identity]) == op['interfaceName']:
                raise ValueError('foreign boot interface profile refused')
        self.cached(op)
        if any(link['ifname'] == op['interfaceName'] for link in self.ip('-d', 'link', 'show')):
            self.configuration_matches(op, row['owner'])
            return {'wasActive':True}
        before, paths = super().preflight(op, protected)
        return {'wasActive':False, 'before':before, 'paths':paths, 'nmOwner':self.manager_instance()}

    def restore(self, row, protected):
        op = row['authorization']['operation']
        plan = row['bootRestore']['plan']
        if plan['wasActive']:
            self.configuration_matches(op, row['owner'])
            return
        if self.snapshot() != plan['before'] or any(self.route_get(address) != path for address, path in plan['paths'].items()):
            raise ValueError('boot restoration precondition changed')
        self.configure(op)
        plan['activationCompleted'] = True
        self.configuration_matches(op, row['owner'])
        if any(self.route_get(address) != path for address, path in plan['paths'].items()):
            raise ValueError('protected boot path changed')
        # No handshake or packet success is inferred here. Existing verifier proof is historical.

    def undo_restore(self, row):
        op = row['authorization']['operation']
        plan = row['bootRestore'].get('plan')
        if plan is None or plan['wasActive']:
            return
        self.check_file(op, row['owner'])
        if not self.cached(op):
            raise ValueError('boot activation cache ownership unavailable')
        active = self.run(['nmcli', '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active']).splitlines()
        observed_active = any(line.split(':', 1)[0] == op['profileUuid'] for line in active)
        if any(link['ifname'] == op['interfaceName'] for link in self.ip('-d', 'link', 'show')):
            if not self.owned(op, row['owner']):
                raise ValueError('boot activation ownership unavailable')
        # Activation is asynchronous inside NM. Cancel the UUID even before a kernel
        # interface appears; killing nmcli alone does not cancel NM's pending work.
        if observed_active:
            self.run(['nmcli', '--wait', '10', 'connection', 'down', 'uuid', op['profileUuid']])
        active_after = self.run(['nmcli', '-t', '-f', 'UUID,DEVICE', 'connection', 'show', '--active']).splitlines()
        if any(line.split(':', 1)[0] == op['profileUuid'] for line in active_after):
            raise ValueError('boot activation cancellation unverified')
        if not observed_active and not plan.get('activationCompleted') and self.manager_instance() == plan.get('nmOwner'):
            # A timed-out method might still be queued. Preserve recovery debt until the
            # UUID can be explicitly cancelled or a new NM instance proves it cannot finish.
            raise ValueError('NetworkManager activation outcome uncertain')
        if self.snapshot() != plan['before'] or any(self.route_get(address) != path for address, path in plan['paths'].items()):
            raise ValueError('boot activation undo unverified')
        # The independently confirmed profile and all signed history remain preserved.
