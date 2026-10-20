export {
  POLICY_DOCUMENT_SCHEMA,
  PolicyStoreError,
  emptyPolicyDocument,
  loadPolicyDocument,
  savePolicyDocument,
  putPolicy,
  removePolicy,
  replacePolicyPlacements,
  type PolicyDocument,
  type PolicyPlacement,
} from "./policy-store.ts";
export {
  SitePolicyError,
  applyPolicyDocument,
  policiesFromSite,
  placementsFromSite,
  type PolicyBearingSite,
} from "./site-policy.ts";
export {
  ENROLLMENT_SCHEMA,
  NODE_TOKEN_PREFIX,
  DEFAULT_NODE_TOKEN_TTL_SEC,
  MAX_NODE_TOKEN_TTL_SEC,
  MAX_PENDING_CSRS_PER_HOST,
  EnrollmentError,
  emptyEnrollmentDocument,
  initializeEnrollmentDocument,
  loadEnrollmentDocument,
  requireEnrollmentDocument,
  saveEnrollmentDocument,
  withEnrollmentTransaction,
  createNodeToken,
  beginHostDeregistration,
  recordHostDeregistrationReplication,
  reconcileHostDeregistrationRelays,
  confirmHostInfrastructureDestroyed,
  completeHostDeregistrationPolicy,
  revokeNodeToken,
  lookupNodeToken,
  looksLikeNodeToken,
  validateNodeCsr,
  validateNodeCsrAsync,
  preflightNodeCsr,
  touchExistingNodeCsr,
  submitValidatedNodeCsr,
  submitNodeCsr,
  rejectNodeCsr,
  reopenRetiredHostname,
  validateNodeCertificate,
  storeNodeCertificate,
  fetchNodeCertificate,
  revokeCertificate,
  createAppToken,
  revokeAppToken,
  looksLikeAppToken,
  lookupAppToken,
  appTokenAllowsHostname,
  appTokenCreatedBy,
  normalizeEnrollmentHostname,
  normalizeHostLifecycleId,
  normalizeExternalOperationId,
  APP_TOKEN_PREFIX,
  APP_TOKEN_SCOPES,
  DEFAULT_APP_TOKEN_TTL_SEC,
  MAX_APP_TOKEN_TTL_SEC,
  type AppTokenRecord,
  type AppTokenScope,
  type EnrollmentDocument,
  type EnrollmentAuditEvent,
  type NodeTokenRecord,
  type NodeCsrRecord,
  type ValidatedNodeCsr,
  type NodeCsrPreflight,
  type CsrStatus,
  type CertificateRevocation,
  type HostDeregistrationRecord,
  type HostDeregistrationRequest,
  type HostDeregistrationCredentialState,
  type HostDeregistrationRelay,
  type HostLifecycleTombstone,
  type RevocationReplicationResult,
} from "./enrollment-store.ts";
export { certificateIsRevoked, peerFingerprint256, type RevocationSourceFormat } from "./certificate-revocation.ts";
export {
  MAX_REVOCATION_ROWS,
  MAX_REVOCATION_SNAPSHOT_BYTES,
  initializeRevocationSnapshot,
  parseRevocationSnapshot,
  serializeRevocationSnapshot,
  writeRevocationSnapshot,
  type RevocationSnapshot,
} from "./revocation-snapshot.ts";
export {
  RevocationWriterUnavailable,
  installRevocationSnapshot,
  startRevocationWriter,
  type RevocationWriterOptions,
} from "./revocation-writer.ts";

export {
  DEFAULT_CONFIG,
  defineConfig,
  isProtectedHost,
  tableRef,
  type ArtifactStore,
  type BaselineRule,
  type HookPolicy,
  type Config,
  type RelayConfig,
  type TlsConfig,
  type WorkloadConfig,
} from "./config.ts";

export {
  K8S_KINDS,
  NO_VALUE_KINDS,
  OBJECT_REF_PREFIX,
  PolicyError,
  isPortsRef,
  isWorkload,
  mergePolicy,
  normalizePolicy,
  normalizePorts,
  policyFingerprint,
  type DenyMode,
  type Endpoint,
  type EndpointKind,
  type Policy,
  type PolicyAction,
  type Proto,
  type ResolveCidrs,
} from "./policy.ts";

export {
  DEFAULT_MANAGED_BY,
  CiliumRenderError,
  assignsToWorkloadLayer,
  membershipJumps,
  podsFromMembership,
  selectorsToWatch,
  DEFAULT_JUMP_LIMITS,
  planCiliumPolicies,
  renderCiliumPolicies,
  type CiliumDenyRule,
  type CiliumEgressRule,
  type CiliumIngressRule,
  type CiliumItem,
  type CiliumNetworkPolicy,
  type CiliumPlan,
  type CiliumPortRule,
  type CiliumRenderInput,
  type CiliumSkipped,
  type CiliumWarning,
  type EndpointSelector,
  type MatchLabels,
  type ResolvePods,
  type ResolveService,
  type MembershipJump,
  type JumpLimits,
  type NamespaceIngressBaseline,
  type SelectorEgressBaseline,
  type ServiceSelector,
  type WorkloadBaseline,
} from "./cilium.ts";

export {
  normalizeObject,
  type AddressObject,
  type FirewallObject,
  type ObjectKind,
  type ServiceObject,
} from "./objects.ts";

export {
  baselineConflict,
  cidrsOverlap,
  familyOf,
  groupByFamily,
  planHostRuleset,
  RenderError,
  portsOverlap,
  renderHostRuleset,
  type EgressItem,
  type Family,
  type InputItem,
  type Match,
  type PlannedRule,
  type Ruleset,
  type RulesetPlan,
  type Skipped,
  type Verdict,
} from "./nft.ts";

export { renderHostRulesetJson, type JsonRuleset } from "./nft-json.ts";

export {
  artifactMatches,
  hasDrifted,
  missingObjects,
  workloadStatus,
  MIN_AGENT_SCHEMA,
  ROLLOUT_ORDER,
  SCHEMA_VERSION,
  schemaSupported,
  type ApplyState,
  type Artifact,
  type Generation,
  type Heartbeat,
  type HeartbeatReply,
  type Manifest,
  type ManifestEntry,
  type RolloutGate,
  type RolloutStage,
  type RulesetEvent,
  type SelectorMembership,
  type WatchSelectors,
  type WorkloadArtifact,
  type WorkloadEntry,
} from "./protocol.ts";

export {
  emptyState,
  fleetView,
  handleHeartbeat,
  loadManifest,
  peerCN,
  startRelay,
  type FleetView,
  type HeartbeatOutcome,
  type HostView,
  type RelayOptions,
  type RelayState,
} from "./relay.ts";

export {
  siteView,
  siteNeedsAttention,
  type RelayResult,
  type RelaySource,
  type SiteView,
} from "./manager.ts";

export { pollRelays, startManager, type ManagerOptions } from "./manager-server.ts";

export { computeGate, rolloutBlockers, type HostStatus } from "./rollout.ts";

export {
  CA_DAYS,
  CURVE,
  LEAF_DAYS,
  PkiError,
  RENEW_BEFORE_DAYS,
  certStatus,
  fileBaseFor,
  planCert,
  requiredCerts,
  roleFromFileBase,
  subjectFor,
  type CertPlan,
  type CertRequest,
  type CertRole,
  type CertStatus,
} from "./pki.ts";

export {
  planPublish,
  PublishError,
  writePublish,
  type PublishHost,
  type PublishInput,
  type PublishPlan,
  type PublishedArtifact,
  type PublishedWorkload,
} from "./publish.ts";

export {
  bundleFromPlan,
  bundleHash,
  BundleError,
  planHash,
  validateBundle,
  writeBundle,
  type PlanBundle,
} from "./bundle.ts";

export {
  ArtifactSignatureError,
  AuthorizationTimestampIssuer,
  artifactAuthorizationPayloadHash,
  artifactSigningKeyId,
  artifactSigningTrustSummary,
  decodeHostArtifactEnvelope,
  encodeAuthorizedArtifactBundle,
  encodeHostArtifactEnvelope,
  loadAuthorizedArtifactBundle,
  signAuthorizedArtifactBundle,
  signHostArtifactAuthorization,
  validateAuthorizedArtifactBundle,
  verifyHostArtifactAuthorization,
  writeAuthorizedArtifactBundle,
  type ArtifactManifestHeader,
  type ArtifactSigningTrustRings,
  type ArtifactSigningTrustSummary,
  type AuthorizationMode,
  type AuthorizedArtifactBundle,
  type HostArtifactAuthorizationPayload,
  type HostArtifactEnvelope,
} from "./artifact-signature.ts";

export {
  ApprovalError,
  approve,
  claimForPublish,
  DEFAULT_LIMITS,
  emptyApprovals,
  listPlans,
  propose,
  release,
  sweep,
  type ApprovalLimits,
  type ApprovalState,
  type Plan,
  type PlanSummary,
} from "./approval.ts";

export {
  validateNetworkInventory,
  type NetworkManagement,
  type NetworkResource,
  type NetworkInventoryResource,
  type NetworkInventoryIssue,
  type InventorySite,
  type InventoryNode,
  type InventoryGateway,
  type InventoryNetwork,
  type InventorySubnet,
  type InventoryAddressPool,
  type InventoryInterface,
  type InventoryRoute,
  type InventoryRoutingDomain,
  type InventoryDomainConnection,
  type InventoryLearnedRoute,
  type NetworkPurpose,
  type AddressPoolPurpose,
} from "./network-inventory.ts";

export {
  NetworkRegistryStore,
  NetworkRegistryError,
  MAX_NETWORK_REGISTRY_RESOURCES,
  MAX_NETWORK_REGISTRY_INPUT_BYTES,
  type NetworkRegistryDocument,
  type NetworkRegistryRevision,
  type NetworkRegistryMutation,
} from "./network-registry.ts";

export {
  NetworkObservationStore,
  validateNetworkObservation,
  observationFreshness,
  NETWORK_COLLECTOR_NAMES,
  type NetworkObservationReport,
  type NetworkObservationRecord,
  type NetworkCollectorObservation,
  type CollectorStatus,
} from "./network-observation.ts";

export { matchNetworkInventory, type NetworkIdentityBinding, type NetworkMatchStatus, type NetworkMatch, type NetworkMatchEvidence, type NetworkMatchingInput, type NetworkMatchingResult } from "./network-matching.ts";
export { buildNetworkPlan, type NetworkPlanInput, type NetworkPlan, type NetworkPlanBlocker, type NetworkDependency } from "./network-planner.ts";
export { compileWireGuard, type WireGuardSpec, type WireGuardGatewaySpec, type WireGuardCompilation } from "./network-wireguard.ts";
export { compileFrr, type FrrSpec, type FrrPeerSpec, type FrrCompilation } from "./network-frr.ts";

export { buildNetworkChangeSet, type NetworkChangeSetInput, type NetworkChangeSet, type NetworkChangeOperation } from "./network-change-set.ts";
export { validatePrefixPolicy, type NetworkPrefixPolicy, type PrefixPermission } from "./network-prefix-policy.ts";

export { authorizeNetworkExecution, networkExecutionHash, type NetworkExecutionDraft, type NetworkWireGuardOperation, type NetworkSignedEnvelope } from "./network-execution.ts";
