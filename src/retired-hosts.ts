export const RETIRED_HOSTS_SCHEMA = 1 as const;

export interface RetiredHostsDocument {
  schemaVersion: typeof RETIRED_HOSTS_SCHEMA;
  retiredHosts: Array<{
    hostname: string;
    hostLifecycleId: string;
    externalOperationId: string;
    retiredAt: string;
  }>;
}

const HOSTNAME = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/;
const EXTERNAL_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function parseRetiredHostsDocument(text: string, source = "retired hosts document"): RetiredHostsDocument {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new Error(`${source}: invalid JSON`); }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${source}: expected an object`);
  const value = raw as Record<string, unknown>;
  if (Object.keys(value).some((key) => !["schemaVersion", "retiredHosts"].includes(key))
    || value.schemaVersion !== RETIRED_HOSTS_SCHEMA || !Array.isArray(value.retiredHosts)) {
    throw new Error(`${source}: expected schemaVersion ${RETIRED_HOSTS_SCHEMA} and a retiredHosts array`);
  }
  const retiredHosts = value.retiredHosts.map((raw, index) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error(`${source}: retiredHosts[${index}] must be an object`);
    }
    const entry = raw as Record<string, unknown>;
    if (Object.keys(entry).some((key) => !["hostname", "hostLifecycleId", "externalOperationId", "retiredAt"].includes(key))
      || typeof entry.hostname !== "string" || entry.hostname !== entry.hostname.trim().toLowerCase()
      || !HOSTNAME.test(entry.hostname) || typeof entry.hostLifecycleId !== "string" || !EXTERNAL_ID.test(entry.hostLifecycleId)
      || typeof entry.externalOperationId !== "string" || !EXTERNAL_ID.test(entry.externalOperationId)
      || typeof entry.retiredAt !== "string" || !Number.isFinite(Date.parse(entry.retiredAt))
      || new Date(entry.retiredAt).toISOString() !== entry.retiredAt) {
      throw new Error(`${source}: retiredHosts[${index}] is invalid`);
    }
    return {
      hostname: entry.hostname,
      hostLifecycleId: entry.hostLifecycleId,
      externalOperationId: entry.externalOperationId,
      retiredAt: new Date(entry.retiredAt).toISOString(),
    };
  });
  if (new Set(retiredHosts.map((entry) => entry.hostname)).size !== retiredHosts.length) {
    throw new Error(`${source}: duplicate hostname`);
  }
  return { schemaVersion: RETIRED_HOSTS_SCHEMA, retiredHosts: [...retiredHosts].sort((a, b) => a.hostname.localeCompare(b.hostname)) };
}

export function retireHost(text: string, input: {
  hostname: string; hostLifecycleId: string; externalOperationId: string; retiredAt: string;
}): { content: string; changed: boolean } {
  const { hostname } = input;
  if (hostname !== hostname.trim().toLowerCase() || !HOSTNAME.test(hostname)) {
    throw new Error(`cannot retire non-canonical hostname ${JSON.stringify(hostname)}`);
  }
  const document = parseRetiredHostsDocument(text);
  const existing = document.retiredHosts.find((entry) => entry.hostname === hostname);
  if (existing) {
    if (existing.hostLifecycleId !== input.hostLifecycleId || existing.externalOperationId !== input.externalOperationId) {
      throw new Error(`retired hostname ${hostname} belongs to a different lifecycle or operation`);
    }
    return { content: JSON.stringify(document, null, 2) + "\n", changed: false };
  }
  if (!EXTERNAL_ID.test(input.hostLifecycleId) || !EXTERNAL_ID.test(input.externalOperationId)
    || !Number.isFinite(Date.parse(input.retiredAt))) {
    throw new Error("retirement requires lifecycle, operation and timestamp evidence");
  }
  document.retiredHosts.push({
    hostname, hostLifecycleId: input.hostLifecycleId, externalOperationId: input.externalOperationId,
    retiredAt: new Date(input.retiredAt).toISOString(),
  });
  document.retiredHosts.sort((a, b) => a.hostname.localeCompare(b.hostname));
  return { content: JSON.stringify(document, null, 2) + "\n", changed: true };
}

/** Policy-repository migration seam: exact ids only, never a hostname pattern. */
export function withoutRetiredHosts<
  T extends { id: string },
  D extends { retiredHosts: readonly { hostname: string }[] },
>(
  hosts: readonly T[], document: D,
): T[] {
  const retired = new Set(document.retiredHosts.map((entry) => entry.hostname));
  return hosts.filter((host) => !retired.has(host.id));
}
