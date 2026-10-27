/** Explicit opt-in lab transport. This is not production Relay qualification. */
import { join } from 'node:path';
import type { RelaySource } from '../../src/manager.ts';

export function observationRelays(dir: string, cfg: { lifecycleObservationTransport?: unknown; identity?: { source?: unknown; host?: unknown; nodeId?: unknown } }): RelaySource[] {
  const enabled = cfg.lifecycleObservationTransport === undefined ? false : cfg.lifecycleObservationTransport;
  if (typeof enabled !== 'boolean') throw new Error('explicit boolean observation transport required');
  if (!enabled) return [];
  if (cfg.identity?.source !== 'lab' || cfg.identity?.host !== 'gateway' || cfg.identity?.nodeId !== 'gateway') throw new Error('fixed disposable observation identity required');
  return [{ name: 'lab', url: 'https://192.0.2.1:8444', pkiDir: join(dir, 'relay-operator-pki'), operatorName: 'hp-manager' }];
}
