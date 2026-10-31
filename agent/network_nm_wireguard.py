"""Bounded NM 1.56 keyfile driver; used only through the production Executor writer."""
import hashlib
import os
import re
import sys
import time
from network_executor import LinuxWireGuard
from network_nm_profile import DRIVER, ProfileStore, render


# `nmcli --wait` is how long NM itself may take. The child process needs more than that: the client
# has to start (libnm/GI) and reach D-Bus before the wait even begins. With the cap equal to the wait
# there was no headroom, and a slow boot timed out an activation NM had finished in about a second
# (measured in the Rocky 10.2 TCG lab, 2026-10-30: activated at +1.1 s, the Agent deactivated it at
# +10.3 s). The operation's absolute budgets still bound every child.
NM_WAIT_SEC = 10
NM_CLIENT_HEADROOM_SEC = 10
# After a timed-out `connection up`, how long to keep reading the real state. Read-only; activation is
# never re-issued.
NM_SETTLE_SEC = NM_WAIT_SEC
NM_SETTLE_POLL_SEC = 0.5


class NetworkManagerWireGuard(LinuxWireGuard):
    identity = DRIVER

    def __init__(self, secrets):
        super().__init__(secrets)
        self.store = ProfileStore()
        self.row = None

    def command_timeout(self):
        # Cold libnm/GI startup on the measured TCG guest exceeds the kernel driver's
        # five-second command cap. Every child still shares the operation's absolute budget.
        limits=[value-time.monotonic() for value in [self.deadline,self.command_deadline] if value is not None]
        remaining=min([NM_WAIT_SEC+NM_CLIENT_HEADROOM_SEC]+limits)
        if remaining<=0:raise RuntimeError('network operation budget elapsed')
        return remaining

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
            self.run(['nmcli', '--wait', str(NM_WAIT_SEC), 'connection', 'load', path])
            if not self.cached(op):
                raise ValueError('persistent profile load unverified')
        try:
            self.run(['nmcli', '--wait', str(NM_WAIT_SEC), 'connection', 'up', 'uuid', op['profileUuid']])
        except RuntimeError as error:
            if not str(error).startswith('network command unavailable or timed out:'):
                raise
            # The client timing out says nothing about NM: the activation may have completed. Read the
            # real NM/kernel state instead of deciding from the child's exit; never re-activate.
            settled, last = self.activation_settled(op)
            if not settled:
                raise RuntimeError(f'{error}; activation state not settled: {last}') from None
        self.check_file(op, self.row['owner'])

    def activation_settled(self, op):
        """(True, "") once NM and the kernel show exactly the approved activation, else (False, reason).

        Bounded by NM_SETTLE_SEC **and** by the operation's own deadlines: the loop is not a child, so
        `command_timeout` does not bound it. A budget/deadline error from a read ends it at once.
        """
        settled, error = self._settle(lambda: self.configuration_matches(op, self.row['owner']))
        return settled, '' if settled else (str(error) or type(error).__name__)

    def _settle(self, probe):
        """(True, None) once `probe` stops raising, else (False, last error).

        NM finishes activation and device deletion asynchronously, so a check made right after the
        nmcli call can see the previous state. Bounded by NM_SETTLE_SEC and by the operation's own
        deadlines (this loop is not a child, so `command_timeout` does not bound it). A
        budget/deadline error from a read ends it at once.
        """
        limits = [v for v in (self.deadline, self.command_deadline) if v is not None]
        settle_until = min([time.monotonic() + NM_SETTLE_SEC] + limits)
        while True:
            try:
                probe()
                return True, None
            except (ValueError, RuntimeError, KeyError, IndexError) as error:
                last = str(error) or type(error).__name__
                if 'budget elapsed' in last or 'deadline elapsed' in last or time.monotonic() >= settle_until:
                    return False, error
            time.sleep(max(0.0, min(NM_SETTLE_POLL_SEC, settle_until - time.monotonic())))

    def routes(self, op):
        # NM activates the exact approved addresses/routes together with the connection.
        # Independent verification and local shape checks remain mandatory before confirm.
        pass

    def kernel_options_owned(self, op):
        if self.run(['wg','show',op['interfaceName'],'fwmark']) != 'off':
            raise ValueError('persistent fwmark ownership conflict')
        keepalive = dict(line.split() for line in self.run(['wg','show',op['interfaceName'],'persistent-keepalive']).splitlines())
        expected = {peer['publicKey'] for peer in op['peers']}
        if any(public not in expected or value != '1' for public,value in keepalive.items()):
            raise ValueError('persistent keepalive ownership conflict')

    def fingerprint(self, op):
        value = super().fingerprint(op)
        value['fwmark'] = self.run(['wg','show',op['interfaceName'],'fwmark'])
        value['keepalive'] = self.run(['wg','show',op['interfaceName'],'persistent-keepalive'])
        return value

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
        self.kernel_options_owned(op)
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
            self.store.remove_tombstone(op['profileUuid'])
            self.store.barrier()
            return
        cached = self.cached(op)
        if present and not self.owned(op, owner):
            raise ValueError('persistent interface ownership unavailable')
        if cached:
            self.run(['nmcli', '--wait', str(NM_WAIT_SEC), 'connection', 'delete', 'uuid', op['profileUuid']])
        self.store.remove(op['profileUuid'], self.row['persistence']['profileHash'])
        def gone():
            if op['profileUuid'] in self.profiles() or any(link['ifname'] == op['interfaceName'] for link in self.ip('-d', 'link', 'show')):
                raise ValueError('persistent rollback removal unverified')
        # NM deletes the device after `connection delete` returns; a check made at once wrote a
        # durable rollback-failed that a retry under 1 s later cleared (2026-10-30 lab, review M6).
        removed, error = self._settle(gone)
        if not removed:
            raise error
        try:
            self.store.read(op['profileUuid'])
        except FileNotFoundError:
            self.store.remove_tombstone(op['profileUuid'])
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
            self.run(['nmcli', '--wait', str(NM_WAIT_SEC), 'connection', 'down', 'uuid', op['profileUuid']])
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
