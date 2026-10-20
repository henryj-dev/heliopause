"""Bounded network mailbox beside the existing heartbeat loop; one writer admission owner."""
import copy
import hashlib
import os
import threading
import time
from network_executor import Executor, TERMINAL, atomic, read_file, read_json, safe_diagnostic

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
        self.worker_fd = None
        self.observations = {}
        self.last_observation = float('-inf')
        self.snapshot = {'mode': 'integrated', 'networkEnabled': enabled, 'activeWriter': None,
                         'network': {'state': 'disabled'}, 'heartbeat': {}, 'discovery': {}}
        self.status_lock = threading.Lock()
        self.executor = executor
        if config is not None and executor is None:
            config = {**config, 'enabled': enabled and config.get('enabled') is True}
            self.enabled = config['enabled']
            self.snapshot['networkEnabled'] = self.enabled
            self.executor = Executor(config, directory)

    def error(self, key, reason):
        # Codes only: raw exceptions may contain credentials or secret paths.
        with self.status_lock:
            self.errors[key] = reason

    def firewall_state(self):
        # Legacy load_state projects malformed storage to a default. Admission may not do that.
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
        return self.agent.load_state()

    def firewall_debt(self):
        st = self.firewall_state()
        return self.agent._has_live_commitment(st) or st.get('state') in DEBT or st.get('workloadState') in DEBT

    def recover_firewall(self, settle=False):
        # Each recovery is attempted even if a different journal/helper fails.
        for name in ['recover_commitment', 'recover_workload_commitment', 'reconcile_recovered_commitments']:
            try:
                self.firewall_state()
                getattr(self.agent, name)()
            except Exception:
                self.error('firewall-recovery', 'firewall-recovery-unresolved')
        try:
            st = self.firewall_state()
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

    def blocked(self):
        with self.status_lock:
            return bool(self.errors)

    def begin_firewall(self):
        # Heartbeat processing never waits on a network command or its journal lock.
        with self.gate:
            if self.active is not None or self.blocked():
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
        pending = [(tx, row) for tx, row in rows.items() if row['state'] not in TERMINAL]
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
                    self.executor.driver.command_deadline = time.monotonic()+2
                    present = self.executor.driver.owned(row['authorization']['operation'], row['owner'])
                    observed[tx] = {'state': 'matching' if present else 'absent-or-drifted', 'at': time.time()}
                except Exception:
                    observed[tx] = {'state': 'unknown', 'at': time.time()}
                finally:
                    self.executor.driver.command_deadline = None
        with self.status_lock:
            self.snapshot['network'] = {'state': 'recovery-debt' if pending else 'idle',
                'transactions': [{'transactionId': tx, 'state': row['state']} for tx, row in rows.items()],
                'ledger': {'used': len(rows), 'limit': 1024, 'remaining': 1024-len(rows)},
                'confirmedKernel': copy.deepcopy(observed), 'observedAt': time.time()}

    def publish(self):
        if self.worker_fd is None:
            return
        try:
            self.executor.publish_results()
            results = read_json(os.path.join(self.directory, 'terminal-results.json'))
            ack_path = os.path.join(self.directory, 'terminal-acks.json')
            acks = read_json(ack_path) if os.path.exists(ack_path) else {}
            if not isinstance(acks, dict):
                raise ValueError('invalid terminal acknowledgment storage')
            with self.status_lock:
                self.snapshot['terminalDelivery'] = {'results': len(results), 'acknowledged': sum(hashlib.sha256(__import__('network_executor').canonical(r).encode()).hexdigest() in acks for r in results)}
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
        for filename in ['request.json', 'confirm.json']:
            try:
                raw = read_file(os.path.join(self.directory, filename))
            except FileNotFoundError:
                continue
            except Exception:
                self.error('network-mailbox', 'network-mailbox-unreadable')
                continue
            stamp = hashlib.sha256(raw).hexdigest()
            if self.seen.get(filename) == stamp:
                continue
            self.seen[filename] = stamp
            try:
                if filename == 'request.json':
                    self.begin_network()
                    result = self.executor.accept(read_json(os.path.join(self.directory, filename)))
                else:
                    result = self.executor.confirm(read_json(os.path.join(self.directory, filename)))
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
        def loop():
            while not self.agent._stop.is_set():
                try:
                    self.step()
                    self.write_status()
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
        with self.gate:
            result['activeWriter'] = copy.deepcopy(self.active)
        try:
            st = self.firewall_state()
            result['recoveryDebt'] = {'firewall': st.get('state') in DEBT,
                                     'workload': st.get('workloadState') in DEBT,
                                     'network': result['network']['state'] == 'recovery-debt'}
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
