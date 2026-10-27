/** HOST TLS/temporary-store regression, not VM/NM or production Relay qualification. */
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync, execFileSync, type ChildProcess } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Agent, request } from 'node:https';
import { createSecureContext } from 'node:tls';
import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { startManager } from './manager-server.ts';
import { NetworkRegistryStore } from './network-registry.ts';
import { buildNetworkChangeSet } from './network-change-set.ts';
import { networkDigest } from './network-canonical.ts';
import { networkLabInput } from '../examples/network-lab.ts';
import { observationRelays } from '../scripts/network-transaction-lab/manager-options.ts';

const root = mkdtempSync(join(tmpdir(), 'hp-lab-observation-'));
const pki = join(root, 'pki'); mkdirSync(pki);
const identities = ['gateway', 'alice', 'bob', 'hp-manager'];
const clients = new Map<string, Agent>();
let relay: ChildProcess;
let relayPort = 0;
let manager: Awaited<ReturnType<typeof startManager>>;
let managerPort = 0;
const read = (name: string) => readFileSync(join(pki, name));
const cfg = { lifecycleObservationTransport: true, identity: { source: 'lab', host: 'gateway', nodeId: 'gateway' } };
const registryFile = join(root, 'registry.json');

function call(port: number, who: string, path: string, method = 'GET', body?: unknown, exact?: Buffer) {
  const raw = exact ?? (body === undefined ? undefined : Buffer.from(JSON.stringify(body)));
  return new Promise<{ status: number; body: any; raw: Buffer }>((resolveReply, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method, agent: clients.get(who),
      signal: AbortSignal.timeout(5000), headers: { 'content-type': 'application/json', ...(raw === undefined ? {} : { 'content-length': String(raw.length) }) } }, response => {
      const chunks: Buffer[] = []; response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => { const result = Buffer.concat(chunks); try { resolveReply({ status: response.statusCode!, body: JSON.parse(result.toString()), raw: result }); } catch (error) { reject(error); } });
    });
    req.on('error', reject); req.end(raw);
  });
}

before(async () => {
  const ssl = (...args: string[]) => execFileSync('openssl', args, { cwd: pki, stdio: 'pipe' });
  ssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', '/CN=lab-test-ca');
  for (const name of ['manager', ...identities]) {
    ssl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', name + '.key', '-out', name + '.csr', '-subj', '/CN=' + name);
    writeFileSync(join(pki, 'leaf.ext'), 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=' + (name === 'manager' ? 'serverAuth\nsubjectAltName=IP:127.0.0.1\n' : 'clientAuth\n'));
    ssl('x509', '-req', '-in', name + '.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', name + '.pem', '-days', '1', '-extfile', 'leaf.ext');
    if (name !== 'manager') clients.set(name, new Agent({ keepAlive: false, maxCachedSessions: 0, secureContext: createSecureContext({ ca: read('ca.pem'), cert: read(name + '.pem'), key: read(name + '.key') }) }));
  }
  writeFileSync(join(root, 'config.json'), JSON.stringify(cfg));
  const fixture = resolve('scripts/network-transaction-lab');
  relay = spawn('python3', ['-I', '-B', '-c', "import sys;sys.path.insert(0,sys.argv[1]);import relay;s=relay.create_server(sys.argv[2],'127.0.0.1',0);print(s.server_address[1],flush=True);s.serve_forever()", fixture, root], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; let errors = '';
  relay.stderr!.on('data', bytes => errors += bytes);
  await new Promise<void>((resolveReady, reject) => {
    const timeout = setTimeout(() => reject(new Error('lab TLS relay readiness timeout: ' + errors)), 5000);
    relay.once('exit', code => { clearTimeout(timeout); reject(new Error('lab TLS relay exited ' + code + ': ' + errors)); });
    relay.stdout!.on('data', bytes => { output += bytes; if (output.includes('\n')) { relayPort = Number(output.trim()); clearTimeout(timeout); resolveReady(); } });
  });
  const operator = join(root, 'relay-operator-pki'); mkdirSync(operator, { mode: 0o700 });
  for (const [name, from] of [['ca.pem', 'ca.pem'], ['operator-hp-manager.pem', 'hp-manager.pem'], ['operator-hp-manager.key', 'hp-manager.key']]) writeFileSync(join(operator, name!), read(from!), { mode: 0o600 });
  const managerKey = generateKeyPairSync('ed25519'); const verifier = generateKeyPairSync('ed25519');
  manager = await startManager({ hostname: '127.0.0.1', port: 0,
    relays: observationRelays(root, cfg).map(source => ({ ...source, url: 'https://127.0.0.1:' + relayPort })),
    tls: { certFile: join(pki, 'manager.pem'), keyFile: join(pki, 'manager.key'), caFile: join(pki, 'ca.pem') },
    operatorCNs: ['alice', 'bob'], writerCNs: ['alice', 'bob'], networkRegistryFile: registryFile, networkObservationsDir: join(root, 'observations'),
    networkExecutionTargets: [{ source: 'lab', host: 'gateway', nodeId: 'gateway', journalId: 'e'.repeat(32), certificateSha256: createHash('sha256').update(new X509Certificate(read('gateway.pem')).raw).digest('hex') }],
    networkVerifierKeys: [verifier.publicKey], artifactSigning: { privateKey: managerKey.privateKey }, log: () => {} });
  managerPort = (manager.server.address() as { port: number }).port;
});

after(async () => {
  for (const agent of clients.values()) agent.destroy();
  if (manager) await new Promise<void>(done => manager.server.close(() => done()));
  if (relay && relay.exitCode === null) { const exited = once(relay, 'exit'); relay.kill('SIGTERM'); await exited; }
  rmSync(root, { recursive: true, force: true });
});

test('lab observation transport is opt-in with an explicit service identity', () => {
  assert.deepEqual(observationRelays(root, {}), []);
  assert.equal(observationRelays(root, cfg)[0]!.operatorName, 'hp-manager');
  assert.equal(observationRelays(root, cfg)[0]!.pkiDir, join(root, 'relay-operator-pki'));
  for (const invalid of ['true', null, 1]) assert.throws(() => observationRelays(root, { ...cfg, lifecycleObservationTransport: invalid }), /boolean/);
  assert.throws(() => observationRelays(root, { ...cfg, identity: { source: 'foreign' } }), /identity/);
});

test('observation CN/host, original JSON and request bounds are enforced at TLS fixture', async () => {
  const raw = Buffer.from('{"host":"gateway","report":{"schemaVersion":1e0,"original":"unchanged"}}');
  for (const who of ['alice', 'bob', 'hp-manager']) assert.equal((await call(relayPort, who, '/network/observations', 'POST', undefined, raw)).status, 403);
  for (const who of ['gateway', 'alice', 'bob']) assert.equal((await call(relayPort, who, '/network/observations')).status, 403);
  assert.equal((await call(relayPort, 'gateway', '/network/observations', 'POST', { host: 'other', report: {} })).status, 400);
  assert.equal((await call(relayPort, 'gateway', '/network/observations', 'POST', undefined, Buffer.from('{"host":"gateway","host":"gateway","report":{}}'))).status, 400);
  assert.equal((await call(relayPort, 'gateway', '/network/observations', 'POST', undefined, Buffer.from([255]))).status, 400);
  assert.equal((await call(relayPort, 'gateway', '/network/observations', 'POST', undefined, Buffer.alloc(128 * 1024 + 1, 32))).status, 413);
  const first = await call(relayPort, 'gateway', '/network/observations', 'POST', undefined, raw);
  assert.equal(first.status, 200); assert.equal(first.body.transportReceiptOnly, true);
  const duplicate = await call(relayPort, 'gateway', '/network/observations', 'POST', undefined, raw);
  assert.equal(duplicate.body.receivedAt, first.body.receivedAt);
  const observed = await call(relayPort, 'hp-manager', '/network/observations');
  assert.ok(observed.raw.includes(Buffer.from('"schemaVersion":1e0,"original":"unchanged"')));
  assert.equal(observed.body.observations[0].receivedAt, first.body.receivedAt);
  assert.equal(readFileSync(join(root, 'observation-transport', 'body-' + createHash('sha256').update(raw).digest('hex') + '.bin')).equals(raw), true);
  // A syntactically valid opaque report is a transport receipt, not schema approval.
  const rejected = await call(managerPort, 'alice', '/api/network/observations/lab/gateway');
  assert.equal(rejected.status, 503); assert.equal(rejected.body.observation, null);
});

test('real TLS upload reaches production Manager cache and distinct Alice/Bob HTTP issuance', async () => {
  const input = networkLabInput();
  for (const resource of input.registry.resources) {
    resource.management = { ...resource.management };
    if (resource.id === 'n0') resource.id = 'gateway';
    if ('nodeId' in resource && resource.nodeId === 'n0') resource.nodeId = 'gateway';
    if (resource.management.mode === 'managed') resource.management.driver = 'wg-quick';
    if (resource.kind === 'interface' && resource.id === 'wg0') { resource.name = 'hpcccccccccccc'; if (resource.management.mode === 'managed') resource.management.driver = 'networkmanager-wireguard-1.56-v1'; }
    if (resource.kind === 'route' && resource.interfaceId === 'wg0') {
      resource.protocol = 'static'; resource.metric = 42760;
      if (resource.management.mode === 'managed') resource.management.driver = 'networkmanager-wireguard-1.56-v1';
    }
  }
  const store = new NetworkRegistryStore(registryFile);
  const registry = store.mutate(0, 'fixture', { action: 'replace', resources: input.registry.resources }); store.initializeExecutions();
  const stamp = new Date().toISOString(); const report = structuredClone(input.observations[0]!.report);
  report.startedAt = stamp; report.completedAt = stamp;
  for (const result of Object.values(report.observations)) { result.startedAt = stamp; result.completedAt = stamp; }
  assert.equal((await call(relayPort, 'gateway', '/network/observations', 'POST', { host: 'gateway', report })).status, 200);
  const fetched = await call(managerPort, 'alice', '/api/network/observations/lab/gateway'); assert.equal(fetched.status, 200);
  // The API adds display-only freshness/collector summaries. They are not part
  // of the source-bound stored record that Manager networkEvidence commits.
  const { freshness: _freshness, collectors: _collectors, ...observation } = fetched.body.observation;
  assert.equal(observation.source, 'lab'); assert.deepEqual(observation.report, report); assert.equal(typeof observation.relayReceivedAt, 'string');
  const target = { source: 'lab', host: 'gateway', nodeId: 'gateway' };
  const now = Date.now(), collectedAt = Date.parse(stamp);
  const review = buildNetworkChangeSet({ id: 'execution-review', registry, expectedRegistryRevision: registry.revision, now: collectedAt, observations: [observation], bindings: [{ ...target, siteId: 's0' }] });
  const operation = { driver: 'networkmanager-wireguard-1.56-v1', interfaceId: 'wg0', interfaceName: 'hpcccccccccccc', address: '198.51.100.1/32', mtu: 1420, listenPort: 51820, secretRef: 'local', publicKey: Buffer.alloc(32, 1).toString('base64'), peers: [{ publicKey: Buffer.alloc(32, 2).toString('base64'), endpoint: '203.0.113.2:51820', allowedIps: ['198.51.100.2/32'] }], routes: ['198.51.100.2/32'], profileUuid: 'cccccccc-cccc-cccc-cccc-cccccccccccc', bootPolicy: 'agent-confirmed-only' };
  const draft = { schemaVersion: 2, journalId: 'e'.repeat(32), transactionId: 'c'.repeat(32), target, registryRevision: registry.revision, resources: registry.resources.map(resource => ({ id: resource.id, generation: resource.generation })), desiredDigest: review.desiredDigest, reviewHash: review.contentHash, artifactHash: networkDigest(operation), observation: { digest: networkDigest(observation), collectedAt, maxAgeMs: 30000 }, localPrecondition: 'a'.repeat(64), operation, issuedAt: now, expiresAt: now + 30000, rollbackAt: now + 60000 };
  assert.equal((await call(managerPort, 'hp-manager', '/api/network/execution/propose', 'POST', { draft })).status, 403);
  const proposed = await call(managerPort, 'alice', '/api/network/execution/propose', 'POST', { draft }); assert.equal(proposed.status, 201, JSON.stringify(proposed.body));
  const hash = proposed.body.hash;
  assert.equal((await call(managerPort, 'alice', '/api/network/execution/approve', 'POST', { hash })).status, 403);
  assert.equal((await call(managerPort, 'bob', '/api/network/execution/approve', 'POST', { hash })).status, 200);
  const authorized = await call(managerPort, 'alice', '/api/network/execution/authorize', 'POST', { hash }); assert.equal(authorized.status, 200, JSON.stringify(authorized.body));
  const payload = JSON.parse(Buffer.from(authorized.body.envelope.payload, 'base64url').toString());
  assert.equal(payload.approval.proposedBy, 'alice'); assert.equal(payload.approval.approvedBy, 'bob');
  assert.deepEqual(payload.observation, draft.observation); assert.equal(store.executionStatus().fence!.transactionId, draft.transactionId);
  // No direct cache construction, private Manager signing or alternate approval implementation above.
  const cache = join(root, 'observations', createHash('sha256').update('lab').digest('hex'));
  const filename = readdirSync(cache).find(name => /^[a-f0-9]{64}\.json$/.test(name))!;
  const priorCache = readFileSync(join(cache, filename));
  assert.equal((await call(relayPort, 'gateway', '/network/observations', 'POST', { host: 'gateway', report: { invalid: true } })).status, 200);
  const invalid = await call(managerPort, 'alice', '/api/network/observations/lab/gateway');
  assert.equal(invalid.body.relayStatus, 'unavailable');
  assert.deepEqual(invalid.body.observation.report, report);
  assert.equal(readFileSync(join(cache, filename)).equals(priorCache), true);
});

test('default legacy heartbeat and firewall fixture behavior remains separate', async () => {
  assert.equal((await call(relayPort, 'gateway', '/heartbeat', 'POST', { schemaVersion: 1, applied: { state: 'confirmed', generation: null } })).status, 200);
  writeFileSync(join(root, 'firewall-envelope.json'), '{"fixture":"original"}');
  const artifact = await call(relayPort, 'gateway', '/artifact'); assert.deepEqual(artifact.body, { fixture: 'original' });
  writeFileSync(join(root, 'fail-pending'), '');
  assert.equal((await call(relayPort, 'gateway', '/heartbeat', 'POST', { schemaVersion: 1, applied: { state: 'pending' } })).status, 503);
});

test('temporary store controls run in the root suite', () => {
  const result = spawnSync('python3', ['-B', 'scripts/network-transaction-lab/test_observation_fixture.py'], { encoding: 'utf8', stdio: 'pipe' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /Ran 9 tests/);
  assert.match(result.stderr, /\nOK\n/);
});

test('default fixture startup does not create or activate the observation transport', () => {
  const legacy = join(root, 'legacy'); mkdirSync(legacy);
  writeFileSync(join(legacy, 'config.json'), '{}');
  // The legacy TLS paths are ordinary temporary fixture inputs, unrelated to site PKI.
  mkdirSync(join(legacy, 'pki'));
  for (const name of ['manager.pem', 'manager.key', 'ca.pem']) writeFileSync(join(legacy, 'pki', name), read(name));
  const code = "import sys;sys.path.insert(0,sys.argv[1]);import relay;from unittest.mock import patch\nwith patch.object(relay,'ObservationTransport',side_effect=AssertionError('unexpected opt-in')):\n s=relay.create_server(sys.argv[2],'127.0.0.1',0)\n assert s.observation_transport is None\n s.server_close()\n";
  execFileSync('python3', ['-I', '-B', '-c', code, resolve('scripts/network-transaction-lab'), legacy], { stdio: 'pipe' });
  assert.equal(readdirSync(legacy).includes('observation-transport'), false);
});
