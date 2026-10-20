/** Persistent desired inventory only. Nothing in this store authorizes a network apply. */
import { createHash } from "node:crypto";
import { mkdirSync, existsSync, openSync, closeSync, fsyncSync, constants } from "node:fs";
import { dirname } from "node:path";
import { withNetworkRegistryLock } from './network-registry-lock.ts';
import { NETWORK_EXECUTION_CAPACITY, validateExecutionState, type NetworkExecutionState, type NetworkExecutionRecord } from './network-execution-state.ts';
import type { NetworkSignedEnvelope } from './network-execution.ts';
import { cidrRange } from "./nft.ts";
import { atomicWriteFile, readBoundedStoreFile } from "./json-store.ts";
import { validateNetworkInventory, type NetworkInventoryIssue, type NetworkInventoryResource, type NetworkManagement } from "./network-inventory.ts";

export const MAX_NETWORK_REGISTRY_RESOURCES = 512;
export const MAX_NETWORK_REGISTRY_INPUT_BYTES = 512 * 1024;
const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
const HISTORY_LIMIT = 256;
export interface NetworkRegistryRevision {
  revision: number;
  actor: string;
  at: string;
  action: "create" | "update" | "delete" | "replace";
  changes: Array<{ id: string; before?: string; after?: string }>;
}
export interface NetworkRegistryDocument {
  schemaVersion: 1 | 2;
  execution?: NetworkExecutionState;
  revision: number;
  resources: NetworkInventoryResource[];
  /** Deleted identities cannot be recreated to bypass an ownership-transfer refusal. */
  retiredIds: string[];
  ownershipClaims: Array<{ key: string; management: NetworkManagement }>;
  updatedAt: string | null;
  updatedBy: string | null;
  /** Bounded recent metadata; digests identify exact before/after content, not execution. */
  history: NetworkRegistryRevision[];
}
export type NetworkRegistryMutation =
  | { action: "create"; resource: unknown }
  | { action: "update"; id: string; resource: unknown }
  | { action: "delete"; id: string }
  | { action: "replace"; resources: unknown };
export class NetworkRegistryError extends Error {
  readonly statusCode: number;
  readonly issues?: NetworkInventoryIssue[];
  constructor(message: string, statusCode = 400, issues?: NetworkInventoryIssue[]) { super(message); this.statusCode = statusCode; this.issues = issues; }
}
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const fail = (message: string, code?: number) => new NetworkRegistryError(message, code);
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
const digest = (resource: unknown) => createHash("sha256").update(canonical(resource)).digest("hex");
function ownershipKey(resource: NetworkInventoryResource, byId: ReadonlyMap<string, NetworkInventoryResource>): string | undefined {
  if (resource.kind === "interface") return digest(["interface", resource.nodeId, resource.name]);
  if (resource.kind === "route") {
    const iface = byId.get(resource.interfaceId);
    const range = cidrRange(resource.destination)!;
    if (iface?.kind === "interface") return digest(["route", iface.nodeId, resource.table, range.family, String(range.first), range.bits]);
  }
  return undefined;
}
const empty = (): NetworkRegistryDocument => ({ schemaVersion: 1, revision: 0, resources: [], retiredIds: [], ownershipClaims: [], updatedAt: null, updatedBy: null, history: [] });
function boundedJson(value: unknown): string {
  let serialized: string | undefined;
  try { serialized = JSON.stringify(value); } catch { throw fail("registry input must be JSON"); }
  if (!serialized) throw fail("registry input must be JSON");
  if (Buffer.byteLength(serialized) > MAX_NETWORK_REGISTRY_INPUT_BYTES) throw fail("registry input exceeds size limit", 413);
  return serialized;
}
function validateResources(resources: unknown): asserts resources is NetworkInventoryResource[] {
  if (!Array.isArray(resources)) throw fail("resources must be an array");
  if (resources.some(r => object(r) && (typeof r.id !== "string" || r.id.length > 256))) throw fail("resource id must be no longer than 256 characters");
  if (resources.length > MAX_NETWORK_REGISTRY_RESOURCES) throw fail("registry resource limit exceeded", 413);
  if (resources.some(r => object(r) && r.kind === "learned-route")) throw fail("learned routes belong to observations, not desired inventory");
  if (resources.some(r => object(r) && r.observedGeneration !== undefined)) throw fail("observedGeneration belongs to observations, not desired inventory");
  const issues = validateNetworkInventory(resources);
  if (issues.length) throw new NetworkRegistryError("inventory validation failed", 409, issues.slice(0, 128));
}

export class NetworkRegistryStore {
  readonly path: string;
  constructor(path: string) { this.path = path; }

  read(): NetworkRegistryDocument {
    let text: string;
    try {
      text = readBoundedStoreFile(this.path, MAX_DOCUMENT_BYTES);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return empty();
      if (e instanceof NetworkRegistryError) throw e;
      throw fail("cannot read network registry", 500);
    }
    try {
      const doc: unknown = JSON.parse(text);
      if (!object(doc) || (doc.schemaVersion !== 1 && doc.schemaVersion !== 2) || !Number.isSafeInteger(doc.revision) || Number(doc.revision) < 0 ||
          !Array.isArray(doc.ownershipClaims) || doc.ownershipClaims.length > 4096 || doc.ownershipClaims.some(c => !object(c) || typeof c.key !== "string" || !/^[a-f0-9]{64}$/.test(c.key) || validateNetworkInventory([{ id: "claim", kind: "site", owner: "registry", generation: 1, management: c.management }]).length) ||
          !Array.isArray(doc.retiredIds) || doc.retiredIds.length > 4096 || doc.retiredIds.some(id => typeof id !== "string") ||
          !Array.isArray(doc.history) || doc.history.length > HISTORY_LIMIT ||
          (doc.revision === 0 ? doc.updatedAt !== null || doc.updatedBy !== null : typeof doc.updatedAt !== "string" || typeof doc.updatedBy !== "string")) throw new Error();
      if(doc.schemaVersion===2) validateExecutionState(doc.execution as NetworkExecutionState);
      else if(doc.execution!==undefined) throw new Error('execution requires Registry schema2');
      validateResources(doc.resources);
      if (new Set(doc.retiredIds).size !== doc.retiredIds.length || doc.resources.some(r => (doc.retiredIds as unknown[]).includes(r.id))) throw new Error();
      if (doc.revision === 0 && (doc.resources.length || doc.history.length)) throw new Error();
      if (doc.revision !== 0 && (!doc.history.length || !object(doc.history.at(-1)) || doc.history.at(-1)!.revision !== doc.revision)) throw new Error();
      const claims = new Map((doc.ownershipClaims as Array<{ key: string; management: NetworkManagement }>).map(c => [c.key, c.management]));
      if (claims.size !== doc.ownershipClaims.length) throw new Error();
      const resourcesById = new Map(doc.resources.map(r => [r.id, r]));
      for (const resource of doc.resources) {
        const key = ownershipKey(resource, resourcesById);
        if (key && (!claims.has(key) || canonical(claims.get(key)) !== canonical(resource.management))) throw new Error();
      }
      const history = doc.history;
      if (history.some((h, i) => !object(h) || !Number.isSafeInteger(h.revision) || Number(h.revision) < 1 || Number(h.revision) > Number(doc.revision) ||
          (i > 0 && (!object(history[i - 1]) || Number(history[i - 1]!.revision) + 1 !== h.revision)) ||
          typeof h.actor !== "string" || !h.actor.trim() || h.actor.length > 256 || typeof h.at !== "string" || !Number.isFinite(Date.parse(h.at)) ||
          typeof h.action !== "string" || !["create", "update", "delete", "replace"].includes(h.action) || !Array.isArray(h.changes) || h.changes.length > MAX_NETWORK_REGISTRY_RESOURCES * 2 ||
          h.changes.some(c => !object(c) || typeof c.id !== "string" || c.id.length > 256 || (!c.before && !c.after) ||
            [c.before, c.after].some(d => d !== undefined && (typeof d !== "string" || !/^[a-f0-9]{64}$/.test(d)))))) throw new Error();
      return doc as unknown as NetworkRegistryDocument;
    } catch { throw fail("network registry document is invalid; refusing to overwrite", 500); }
  }

  /** Explicit one-time migration, not an unlock. Old unresolved sidecars are never adopted. */
  initializeExecutions(): void {
    withNetworkRegistryLock(this.path,fail,()=>{
      if(existsSync(this.path+'.execution-fence')) throw fail('legacy execution fence requires reconciliation',409);
      const doc=this.read();
      if(doc.schemaVersion===2) return;
      if(doc.revision===0) throw fail('initialize Registry inventory first',409);
      doc.schemaVersion=2;doc.execution={schemaVersion:1,nextSequence:1,fence:null,records:[]};
      this.writeExecution(doc);
    });
  }

  private requireExecution(doc:NetworkRegistryDocument):NetworkExecutionState {
    if(existsSync(this.path+'.execution-fence')||doc.schemaVersion!==2||!doc.execution) throw fail('execution ledger unavailable or legacy fence unresolved',409);
    return doc.execution;
  }

  executionStatus(): NetworkExecutionState {
    return withNetworkRegistryLock(this.path,fail,()=>{
      const state=this.requireExecution(this.read());
      // Reconcile an earlier rename followed by an uncertain directory-fsync error before any
      // cached authorization can leave this process (including an operator status response).
      const fd=openSync(this.path,constants.O_RDONLY|constants.O_NOFOLLOW);
      try {fsyncSync(fd);} finally {closeSync(fd);}
      const dir=openSync(dirname(this.path),'r');
      try {fsyncSync(dir);} finally {closeSync(dir);}
      return state;
    });
  }

  private writeExecution(doc:NetworkRegistryDocument):void {
    validateExecutionState(doc.execution!);
    const text=JSON.stringify(doc);
    if(Buffer.byteLength(text)>MAX_DOCUMENT_BYTES) throw fail('execution ledger capacity exceeded',413);
    atomicWriteFile(this.path,text);
  }

  executionTransaction<T>(body:(state:NetworkExecutionState,doc:NetworkRegistryDocument)=>T):T {
    return withNetworkRegistryLock(this.path,fail,()=>{
      const doc=this.read();this.requireExecution(doc);
      const result=body(doc.execution!,doc);
      this.writeExecution(doc);
      return result;
    });
  }

  /** One durable Registry replace installs both the exact authorization and its current fence. */
  fenceExecution(revision:number,transactionId:string,issue:(doc:NetworkRegistryDocument)=>NetworkSignedEnvelope,by:string):NetworkSignedEnvelope {
    return withNetworkRegistryLock(this.path,fail,()=>{
      const doc=this.read();this.requireExecution(doc);
      const state=doc.execution!;
      if(state.fence) throw fail('network execution fence requires settlement',409);
      if(state.records.length>=NETWORK_EXECUTION_CAPACITY||state.records.some(r=>r.transactionId===transactionId)) throw fail('execution replay/capacity refusal',409);
      if(doc.revision!==revision) throw fail('registry revision conflict',409);
      const envelope=issue(doc),a=JSON.parse(Buffer.from(envelope.payload,'base64url').toString());
      const record:NetworkExecutionRecord={sequence:state.nextSequence++,transactionId,fenceId:transactionId,planHash:a.approval.planHash,authorization:envelope,authorizationHash:digest(a),target:a.target,journalId:a.journalId,registryRevision:revision,artifactHash:a.artifactHash,issuedAt:a.issuedAt,issuedBy:by,state:'issued',audit:[{action:'issued',actor:by,at:Date.now()}]};
      state.records.push(record);state.fence={transactionId,fenceId:transactionId,authorizationHash:record.authorizationHash,registryRevision:revision};
      this.writeExecution(doc);
      return envelope;
    });
  }

  /** Actor must come from the caller's authenticated principal, never a JSON body field. */
  mutate(expectedRevision: unknown, actor: string, mutation: NetworkRegistryMutation): NetworkRegistryDocument {
    if (!Number.isSafeInteger(expectedRevision) || Number(expectedRevision) < 0) throw fail("expectedRevision must be a nonnegative safe integer");
    if (typeof actor !== "string" || !actor.trim() || actor.length > 256) throw fail("authenticated actor is required");
    const input = JSON.parse(boundedJson(mutation)) as NetworkRegistryMutation;
    return withNetworkRegistryLock(this.path, fail, () => {
      if (existsSync(this.path + ".execution-fence")) throw fail("network execution fence requires reconciliation", 409);
      const current = this.read();
      if(current.execution?.fence) throw fail("network execution fence requires settlement",409);
      if (current.revision !== expectedRevision) throw fail(`registry revision conflict: current revision is ${current.revision}`, 409);
      const before = new Map(current.resources.map(r => [r.id, r]));
      let candidate: unknown[];
      if (input.action === "replace") {
        if (!Array.isArray(input.resources)) throw fail("resources must be an array");
        candidate = input.resources;
      } else if (input.action === "delete") {
        if (!before.has(input.id)) throw fail("resource not found", 404);
        candidate = current.resources.filter(r => r.id !== input.id);
      } else if (input.action === "create" || input.action === "update") {
        if (!object(input.resource) || typeof input.resource.id !== "string") throw fail("resource requires an id");
        if (input.action === "create" && before.has(input.resource.id)) throw fail("resource already exists", 409);
        if (input.action === "update" && (input.id !== input.resource.id || !before.has(input.id))) throw fail("resource id must match an existing resource", 404);
        candidate = [...current.resources.filter(r => input.action !== "update" || r.id !== input.id), input.resource];
      } else throw fail("unknown registry mutation");
      if (candidate.length > MAX_NETWORK_REGISTRY_RESOURCES) throw fail("registry resource limit exceeded", 413);
      const resources = candidate.map(r => {
        if (!object(r) || typeof r.id !== "string") throw fail("resource requires an id");
        const previous = before.get(r.id);
        if (!previous && current.retiredIds.includes(r.id)) throw fail("deleted resource identities cannot be reused; choose a new id", 409);
        if (previous && r.kind !== previous.kind) throw fail("resource kind cannot change", 409);
        if (r.generation !== undefined && r.generation !== (previous?.generation ?? 1)) throw fail("generation is managed by the registry; submit the current generation", 409);
        if (r.observedGeneration !== undefined) throw fail("observedGeneration belongs to observations");
        const oldManagement = previous?.management;
        const management = r.management;
        if (object(management)) {
          if (management.mode === "adopted" && (!oldManagement || canonical(management) !== canonical(oldManagement))) throw fail("adoption execution is not implemented; inventory metadata cannot transfer authority", 403);
          if (oldManagement && canonical(management) !== canonical(oldManagement)) throw fail("management ownership transfer is not implemented", 403);
        }
        const resource = { ...r, generation: previous?.generation ?? 1 };
        if (previous && canonical(resource) !== canonical(previous)) {
          if (previous.generation === Number.MAX_SAFE_INTEGER) throw fail("resource generation exhausted", 409);
          resource.generation++;
        }
        return resource;
      });
      boundedJson(resources);
      validateResources(resources);
      const byId = new Map(resources.map(r => [r.id, r]));
      const ownershipClaims = new Map(current.ownershipClaims.map(c => [c.key, c.management]));
      for (const r of resources) {
        const key = ownershipKey(r, byId);
        if (!key) continue;
        const prior = ownershipClaims.get(key);
        if (prior && canonical(prior) !== canonical(r.management)) throw fail("network ownership claim transfer is not implemented, including rekeyed resources", 403);
        ownershipClaims.set(key, r.management);
      }
      if (ownershipClaims.size > 4096) throw fail("ownership claim capacity exceeded", 409);
      const after = new Map(resources.map(r => [r.id, r]));
      const changes = [...new Set([...before.keys(), ...after.keys()])].sort().flatMap(id => {
        const a = before.get(id); const b = after.get(id);
        if (a && b && canonical(a) === canonical(b)) return [];
        return [{ id, ...(a ? { before: digest(a) } : {}), ...(b ? { after: digest(b) } : {}) }];
      });
      if (!changes.length) return current;
      if (current.revision === Number.MAX_SAFE_INTEGER) throw fail("registry revision exhausted", 409);
      const at = new Date().toISOString();
      const revision = current.revision + 1;
      const retiredIds = [...current.retiredIds, ...[...before.keys()].filter(id => !after.has(id))];
      if (retiredIds.length > 4096) throw fail("retired identity capacity exceeded", 409);
      const doc: NetworkRegistryDocument = { schemaVersion: current.schemaVersion, ...(current.execution?{execution:current.execution}:{}), revision, resources, retiredIds, ownershipClaims: [...ownershipClaims].map(([key, management]) => ({ key, management })), updatedAt: at, updatedBy: actor,
        history: [...current.history, { revision, actor, at, action: input.action, changes }].slice(-HISTORY_LIMIT) };
      const serialized = JSON.stringify(doc);
      if (Buffer.byteLength(serialized) > MAX_DOCUMENT_BYTES) throw fail("registry history exceeds size limit", 413);
      mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
      atomicWriteFile(this.path, serialized);
      return doc;
    });
  }
}
