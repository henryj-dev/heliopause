"""Bounded network mailbox beside the existing heartbeat loop; one writer admission owner."""
import copy
import hashlib
import os
import threading
import time
from network_executor import Executor, TERMINAL, atomic, read_file, read_json, decode_json, safe_diagnostic, validate_execution_config

DEBT = {'prepared', 'pending', 'rollback-failed', 'rollback-incident'}


class Lifecycle:
    def __init__(self, agent, config=None, directory=None, enabled=False, executor=None):
        self.agent = agent
        self.directory = directory
        self.enabled = enabled
        self.gate = threading.Lock()
        self.active = None
        self.errors = {}
        self.seen = {}
        self.thread = None
        self.status_thread = None
        self.worker_fd = None
        self.observations = {}
        self.last_observation = float('-inf')
        self.snapshot = {'mode': 'integrated', 'networkEnabled': enabled, 'activeWriter': None,
                         'network': {'state': 'unconfigured', 'ledger': {'used': None, 'limit': 1024, 'remaining': None}}, 'heartbeat': {}, 'discovery': {'enabled': os.environ.get('HELIOPAUSE_NETWORK_DISCOVERY') == '1'}}
        self.status_lock = threading.Lock()
        self.executor = executor
        if config is not None and executor is None:
            validate_execution_config(config)
            config = {**config, 'enabled': enabled and config.get('enabled') is True}
            self.enabled = config['enabled']
            self.snapshot['networkEnabled'] = self.enabled
            self.executor = Executor(config, directory, event=self.network_event)

    def network_event(self, point):
        # Executor supplies this identity only at its existing durable transition boundary.
        # Telemetry performs no journal, kernel, socket or subprocess operation here.
        tx=getattr(self.executor,'current_transaction',None)
        with self.gate:
            if self.active and self.active['kind']=='network':
                self.active={**self.active,'transactionId':tx,'phase':point}
        with self.status_lock:
            self.snapshot['network']['phase']=point

    def error(self, key, reason):
        # Codes only: raw exceptions may contain credentials or secret paths.
        with self.status_lock:
            self.errors[key] = reason
            if key in {'network-configuration', 'network-recovery'}:
                self.snapshot['network']['state'] = 'unknown'

    def firewall_state(self, mark=False):
        # Legacy load_state projects malformed storage to a default. Admission may not do that.
        marker=self.agent.STATE_FILE+'.required'
        if os.path.exists(marker) and read_json(marker)!={'required':True}:
            raise ValueError('firewall journal marker invalid')
        if os.path.exists(self.agent.STATE_FILE):
            doc = read_json(self.agent.STATE_FILE)
            allowed = {'none', 'unsupported', 'prepared', 'pending', 'confirmed', 'rolled-back', 'rollback-failed', 'rollback-incident'}
            if not isinstance(doc, dict) or doc.get('state') not in allowed or doc.get('workloadState') not in allowed | {None}:
                raise ValueError('firewall journal invalid')
            for state_key, generation_key in [('state', 'generation'), ('workloadState', 'workloadGeneration')]:
                if doc.get(state_key) in DEBT | {'confirmed'} and not isinstance(doc.get(generation_key), str):
                    raise ValueError('firewall commitment identity invalid')
            for field, kind in [('pendingBackup', dict), ('pendingRoutes', list), ('workloadApplied', list)]:
                if doc.get(field) is not None and not isinstance(doc[field], kind):
                    raise ValueError('firewall recovery material invalid')
            backup=doc.get('pendingBackup')
            if backup is not None and (set(backup)!={'elements'} or backup['elements'] is not None and not isinstance(backup['elements'],list)):
                raise ValueError('firewall backup shape invalid')
            if mark and not os.path.exists(marker):atomic(marker,{'required':True})
            defaults=getattr(self.agent,'_EMPTY_STATE',None)
            if defaults is not None:
                return {key:doc.get(key,value) for key,value in defaults.items()}
        elif os.path.exists(marker):
            raise ValueError('required firewall journal missing')
        return self.agent.load_state()

    def firewall_debt(self):
        st = self.firewall_state()
        return self.agent._has_live_commitment(st) or st.get('state') in DEBT or st.get('workloadState') in DEBT

    def recover_firewall(self, settle=False):
        # Each recovery is attempted even if a different journal/helper fails.
        for name in ['recover_commitment', 'recover_workload_commitment', 'reconcile_recovered_commitments']:
            try:
                self.firewall_state(mark=True)
                getattr(self.agent, name)()
            except Exception:
                self.error('firewall-recovery', 'firewall-recovery-unresolved')
        try:
            st = self.firewall_state(mark=True)
            for generation in {st.get('generation'), st.get('workloadGeneration')} - {None}:
                if settle and self.firewall_debt():
                    self.agent.rollback_generation('integrated lifecycle recovery', generation)
        except Exception:
            self.error('firewall-journal', 'firewall-journal-unreadable')

    def recover(self):
        self.recover_firewall(settle=True)
        if self.executor:
            try:
                import fcntl
                if self.worker_fd is None:
                    fd = os.open(os.path.join(self.directory, 'worker.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except Exception:
                        os.close(fd)
                        raise
                    self.worker_fd = fd
                self.executor.recover()
                self.refresh()
            except Exception:
                self.error('network-recovery', 'network-journal-or-recovery-unresolved')
            self.publish()

    def restore_confirmed_boot(self):
        if self.executor is None:
            return
        try:
            if self.worker_fd is None:
                raise ValueError('network worker lock unavailable')
            self.executor.restore_confirmed_boot()
        except Exception:
            self.error('network-boot-restore', 'confirmed-restoration-unresolved')
        self.publish()

    def blocked(self):
        with self.status_lock:
            return bool(self.errors)

    def begin_firewall(self):
        # Heartbeat processing never waits on a network command or its journal lock.
        with self.gate:
            if self.active is not None or self.blocked():
                return False
            try:
                self.firewall_state()
            except Exception:
                self.error('firewall-journal', 'firewall-journal-unreadable')
                return False
            self.active = {'kind': 'firewall', 'transactionId': None, 'startedAt': time.time()}
            return True

    def defer_firewall(self, generation):
        try:
            self.firewall_state()
            self.agent._record_refusal(generation, 'writer busy or recovery unresolved; policy not applied')
        except Exception:
            self.error('firewall-journal', 'firewall-journal-unreadable')

    def end_firewall(self):
        with self.gate:
            if self.active and self.active['kind'] == 'firewall':
                self.active = None

    def begin_network(self):
        with self.gate:
            if self.active is not None or self.blocked():
                raise ValueError('writer busy or recovery unresolved')
            if self.firewall_debt():
                raise ValueError('firewall rollback debt blocks network execution')
            self.active = {'kind': 'network', 'transactionId': None, 'startedAt': time.time()}

    def refresh(self):
        data = self.executor.load()
        rows = data['transactions']
        pending = [(tx, row) for tx, row in rows.items() if row['state'] not in TERMINAL or row.get('bootRestore', {}).get('recovery') == 'rollback-failed' or row.get('bootRestore', {}).get('state') == 'attempting']
        with self.gate:
            if pending:
                tx, _ = pending[0]
                self.active = {'kind': 'network', 'transactionId': tx}
            elif self.active and self.active['kind'] == 'network':
                self.active = None
        # This observation runs only on the network worker, never on the heartbeat thread.
        observed = self.observations
        candidates = [(tx, row) for tx, row in rows.items() if row['state'] == 'confirmed']
        candidates.sort(key=lambda item: observed.get(item[0], {}).get('at', 0))
        for tx, row in candidates[:1] if not pending and time.monotonic()-self.last_observation >= 30 else []:
            self.last_observation = time.monotonic()
            if row['state'] == 'confirmed':
                try:
                    self.executor.select_driver(row['authorization']['operation'], row)
                    budget = 5 if row['authorization']['operation'].get('driver') == 'networkmanager-wireguard-1.56-v1' else 2
                    self.executor.driver.command_deadline = time.monotonic()+budget
                    present = self.executor.driver.owned(row['authorization']['operation'], row['owner'])
                    if present and row['authorization']['operation'].get('driver') == 'networkmanager-wireguard-1.56-v1':
                        self.executor.driver.configuration_matches(row['authorization']['operation'], row['owner'])
                    observed[tx] = {'state': 'matching' if present else 'absent-or-drifted', 'at': time.time()}
                except ValueError:
                    observed[tx] = {'state': 'absent-or-drifted', 'at': time.time()}
                except Exception:
                    observed[tx] = {'state': 'unknown', 'at': time.time()}
                finally:
                    self.executor.driver.command_deadline = None
        with self.status_lock:
            self.snapshot['network'] = {'state': 'recovery-debt' if pending else 'idle',
                'transactions': [{'transactionId': tx, 'state': row['state'],
                                  **({'bootRestore': {key:value for key,value in row['bootRestore'].items() if key in {'bootId','state','currentConnectivity','reason','recovery'}}} if 'bootRestore' in row else {})}
                                 for tx, row in rows.items()],
                'ledger': {'used': len(rows), 'limit': 1024, 'remaining': 1024-len(rows),
                           'bytes':len(__import__('network_executor').canonical(data).encode()),'admissionByteLimit':6*1024*1024,'byteLimit':8*1024*1024},
                'confirmedKernel': copy.deepcopy(observed), 'observedAt': time.time()}

    def publish(self):
        if self.worker_fd is None:
            return
        try:
            self.executor.publish_results()
            results = read_json(os.path.join(self.directory, 'terminal-results.json'))
            ack_path = os.path.join(self.directory, 'terminal-acks.json')
            acks = read_json(ack_path) if os.path.exists(ack_path) else {}
            from network_terminal_delivery import validate_acks
            validate_acks(acks)
            with self.status_lock:
                acknowledged=sum(hashlib.sha256(__import__('network_executor').canonical(r).encode()).hexdigest() in acks for r in results)
                self.snapshot['terminalDelivery'] = {'results':len(results),'acknowledged':acknowledged,'pending':len(results)-acknowledged}
            delivery_path=os.path.join(self.directory, 'terminal-delivery-status.json')
            if os.path.exists(delivery_path):
                delivery=read_json(delivery_path)
                allowed={None,'identity-or-certificate-refused','settlement-refused','tls-authentication-failed','local-configuration-or-outbox-invalid','manager-transport-unavailable'}
                if delivery.get('state') not in {'pending','ready'} or delivery.get('reason') not in allowed:
                    raise ValueError('invalid terminal transport status')
                with self.status_lock:
                    self.snapshot['terminalDelivery']['transport']={k:delivery.get(k) for k in ['state','reason','lastSuccess','lastFailure']}
        except Exception:
            self.error('terminal-outbox', 'terminal-outbox-unavailable')
        else:
            with self.status_lock:
                self.errors.pop('terminal-outbox', None)

    def step(self):
        if not self.executor or self.worker_fd is None:
            return
        # Local recovery always precedes mailbox admission/reporting.
        try:
            self.executor.tick()
            self.refresh()
        except Exception:
            self.error('network-recovery', 'network-journal-or-recovery-unresolved')
        for filename in ['cancel.json', 'request.json', 'confirm.json']:
            try:
                raw = read_file(os.path.join(self.directory, filename))
            except FileNotFoundError:
                continue
            except Exception:
                self.error('network-mailbox', 'network-mailbox-unreadable')
                continue
            stamp = hashlib.sha256(raw).hexdigest()
            info=os.stat(os.path.join(self.directory,filename),follow_symlinks=False)
            delivery=(stamp,info.st_ino,info.st_mtime_ns)
            if self.seen.get(filename) == delivery:
                continue
            self.seen[filename] = delivery
            try:
                if filename == 'cancel.json':
                    result = self.executor.cancel(decode_json(raw))
                elif filename == 'request.json':
                    self.begin_network()
                    result = self.executor.accept(decode_json(raw))
                else:
                    result = self.executor.confirm(decode_json(raw))
                response = {'requestHash': stamp, 'state': result}
            except Exception as error:
                response = {'requestHash': stamp, 'state': 'rejected', 'diagnostic': safe_diagnostic(error)}
            finally:
                try:
                    self.refresh()
                except Exception:
                    self.error('network-recovery', 'network-journal-or-recovery-unresolved')
            atomic(os.path.join(self.directory, 'response.json'), response)
        self.publish()

    def start(self):
        def status_loop():
            while not self.agent._stop.is_set():
                self.write_status()
                self.agent._stop.wait(1)
        self.status_thread=threading.Thread(target=status_loop,name='agent-status',daemon=True)
        self.status_thread.start()
        if not self.executor or self.worker_fd is None:
            return
        with self.gate:
            if self.active is None:
                self.active = {'kind':'network', 'transactionId':None, 'phase':'boot-restore'}
        def loop():
            self.restore_confirmed_boot()
            try:
                self.refresh()
            except Exception:
                self.error('network-recovery', 'network-journal-or-recovery-unresolved')
            while not self.agent._stop.is_set():
                try:
                    self.step()
                except Exception:
                    self.error('network-worker', 'network-worker-step-failed')
                self.agent._stop.wait(.25)
        self.thread = threading.Thread(target=loop, name='network-mailbox', daemon=True)
        self.thread.start()

    def write_status(self):
        try:
            atomic(os.path.join(os.path.dirname(self.agent.STATE_FILE), 'lifecycle-status.json'), self.report())
        except Exception:
            pass

    def report(self):
        with self.status_lock:
            result = copy.deepcopy(self.snapshot)
            result['errors'] = dict(self.errors)
            result['reportedAt'] = time.time()
            result['agentPid'] = os.getpid()
        with self.gate:
            result['activeWriter'] = copy.deepcopy(self.active)
        try:
            st = self.firewall_state()
            result['recoveryDebt'] = {'firewall': st.get('state') in DEBT,
                                     'workload': st.get('workloadState') in DEBT,
                                     'network': 'unknown' if result['network']['state'] == 'unknown' else result['network']['state'] == 'recovery-debt'}
        except Exception:
            result['recoveryDebt'] = {'firewall': 'unknown', 'workload': 'unknown', 'network': 'unknown'}
        return result

    def discovery(self, success):
        with self.status_lock:
            self.snapshot['discovery']['lastSuccess' if success else 'lastFailure'] = time.time()

    def heartbeat(self, success):
        with self.status_lock:
            self.snapshot['heartbeat']['lastSuccess' if success else 'lastFailure'] = time.time()


    def close(self):
        self.agent._stop.set()
        # Never overlap shutdown recovery with a still-running apply. Process death preserves debt.
        if self.thread:
            self.thread.join()
        if self.status_thread:
            self.status_thread.join(timeout=2)
        self.recover_firewall(settle=True)
        if self.executor and self.worker_fd is not None:
            try:
                self.executor.recover()
                self.refresh()
            except Exception:
                self.error('network-recovery', 'network-recovery-unresolved')
            self.publish()
            os.close(self.worker_fd)
            self.worker_fd = None
        return True
