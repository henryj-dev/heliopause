// Operator-facing process output is deliberately separate from the browser catalogue.
// A journal has one deployment language, while an HTTP server can concurrently serve both.

import { pickLang, type Lang } from "./i18n.ts";

export type OperatorLogKey =
  | "server.listening"
  | "server.unhandled"
  | "server.revocationInstalled"
  | "server.manifestLoaded"
  | "server.manifestReloadFailed"
  | "server.stopping"
  | "server.startupManifestUnavailable"
  | "server.missingEnvironment"
  | "server.socketRequired";

/** A typed one-off event for an audit line whose parameters are meaningful only at its call site. */
export interface OperatorLogEvent { en: string; ko: string }

type Params = Record<string, string | number>;

/** Keep each operational sentence together, as with the UI catalogue. */
export const OPERATOR_LOG_MESSAGES: Record<OperatorLogKey, { en: string; ko: string }> = {
  "server.listening": { en: "listening on {address}", ko: "{address}에서 수신 대기 중" },
  "server.unhandled": { en: "unhandled: {error}", ko: "처리되지 않은 오류: {error}" },
  "server.revocationInstalled": {
    en: "installed {count} certificate revocation(s)",
    ko: "인증서 폐기 {count}건을 설치함",
  },
  "server.manifestLoaded": { en: "authorized bundle loaded: generation {generation}", ko: "승인된 번들을 불러옴: 세대 {generation}" },
  "server.manifestReloadFailed": {
    en: "manifest reload failed, keeping previous: {error}",
    ko: "매니페스트 다시 불러오기에 실패하여 이전 버전을 유지함: {error}",
  },
  "server.stopping": { en: "stopping", ko: "중지 중" },
  "server.startupManifestUnavailable": {
    en: "WARNING: manifest not loadable at startup: {error}",
    ko: "경고: 시작 시 매니페스트를 불러올 수 없음: {error}",
  },
  "server.missingEnvironment": { en: "missing required environment: {name}", ko: "필수 환경 변수가 없음: {name}" },
  "server.socketRequired": { en: "exactly one systemd socket is required", ko: "systemd 소켓이 정확히 하나 필요함" },
};

function substitute(text: string, params: Params): string {
  return text.replace(/\{(\w+)\}/g, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole,
  );
}

export function formatOperatorLog(lang: Lang, key: OperatorLogKey, params: Params = {}): string {
  return substitute(OPERATOR_LOG_MESSAGES[key][lang], params);
}

export function formatOperatorEvent(lang: Lang, event: OperatorLogEvent): string {
  return event[lang];
}

/** `HELIOPAUSE_LOG_LANG` is deployment-wide so one journal does not mix request languages. */
export function logLangFromEnv(env: NodeJS.ProcessEnv = process.env): Lang {
  const raw = env.HELIOPAUSE_LOG_LANG;
  if (raw === undefined || raw === "") return "en";
  if (raw === "en" || raw === "ko") return raw;
  throw new Error(`HELIOPAUSE_LOG_LANG must be en or ko, got ${JSON.stringify(raw)}`);
}

/** Removes `--lang=…` or `--lang …`; the remaining argv remains command-specific. */
export function parseCliLang(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): { lang: Lang; argv: string[] } {
  const rest: string[] = [];
  let explicit: string | undefined;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg.startsWith("--lang=")) { explicit = arg.slice("--lang=".length); continue; }
    if (arg === "--lang") {
      const value = argv[++i];
      if (!value || value.startsWith("-")) throw new Error("--lang requires en or ko");
      explicit = value;
      continue;
    }
    rest.push(arg);
  }
  if (explicit !== undefined) {
    if (explicit !== "en" && explicit !== "ko") throw new Error(`--lang must be en or ko, got ${JSON.stringify(explicit)}`);
    return { lang: explicit, argv: rest };
  }
  // POSIX locales commonly use `ko_KR.UTF-8`, whereas Accept-Language uses `ko-KR`.
  const locale = (env.LANG ?? "").split(".")[0]?.replace("_", "-") ?? "";
  return { lang: pickLang({ acceptLanguage: locale }), argv: rest };
}

/**
 * Installs a process-local CLI language.  The commands predate a shared CLI framework, so this
 * deliberately normalizes argv in place before their individual parsers run.  JSON and generated
 * source are left byte-for-byte alone: they are machine interfaces, not prose.
 */
export function installCliLanguage(fallback?: Lang): Lang {
  const originalArgs = process.argv.slice(2);
  const explicit = originalArgs.some((arg) => arg === "--lang" || arg.startsWith("--lang="));
  const parsed = parseCliLang(originalArgs);
  if (!explicit && fallback) parsed.lang = fallback;
  process.argv.splice(2, process.argv.length - 2, ...parsed.argv);
  if (parsed.lang === "en") return parsed.lang;
  const translate = (value: unknown): unknown => typeof value === "string" ? localizeCliText(value) : value;
  const original = { log: console.log, error: console.error, warn: console.warn };
  console.log = (...args: unknown[]) => original.log(...args.map(translate));
  console.error = (...args: unknown[]) => original.error(...args.map(translate));
  console.warn = (...args: unknown[]) => original.warn(...args.map(translate));
  return parsed.lang;
}

/** Exported for focused tests and for commands that write through a stream. */
export function localizeCliText(text: string): string {
  const trimmed = text.trimStart();
  // JSON, generated TypeScript, PEM and terminal control bytes are contracts rather than prose.
  if (/^[{[]/.test(trimmed) || trimmed.startsWith("//") || trimmed.startsWith("export ") || trimmed.startsWith("-----BEGIN") || text.startsWith("\x1b")) return text;
  const phrases: ReadonlyArray<readonly [string, string]> = [
    ["usage:", "사용법:"], ["missing required environment:", "필수 환경 변수가 없음:"],
    ["created", "생성됨"], ["updated", "갱신됨"], ["deleted", "삭제됨"], ["approved", "승인됨"],
    ["published", "발행됨"], ["rejected", "거부됨"], ["revoked", "폐기됨"], ["uploaded", "업로드됨"],
    ["exported", "내보냄"], ["initialized", "초기화됨"], ["wrote", "작성함"], ["written", "작성됨"],
    ["nothing written", "작성된 내용 없음"], ["not written", "작성하지 않음"], ["dry run", "미리 보기 실행"],
    ["failed", "실패"], ["refused", "거부됨"], ["warning", "경고"], ["WARNING", "경고"],
    ["no pending plans", "대기 중인 계획 없음"], ["not reported", "보고되지 않음"],
    ["never used", "사용한 적 없음"], ["pending", "대기 중"], ["active", "활성"],
    ["stopping", "중지 중"], ["shutting down", "종료 중"], ["listening on", "수신 대기:"],
    ["read-only", "읽기 전용"], ["unreachable", "연결할 수 없음"], ["incomplete read", "불완전한 읽기"],
    ["does not export", "내보내지 않음"], ["is required", "필수임"], ["is empty", "비어 있음"],
    ["CA created", "CA 생성됨"], ["subject", "주체"], ["expires", "만료"],
    ["issuing from", "발급 CA"], ["issuing for", "발급 대상"], ["certificate(s)", "인증서"],
    ["nothing due for renewal", "갱신할 인증서 없음"], ["renewing", "갱신 중"],
    ["Distribute per host", "호스트별 배포"], ["every host", "모든 호스트"],
    ["gateway only", "게이트웨이 전용"], ["one host at a time", "한 번에 한 호스트씩"],
    ["signed agent CSR", "에이전트 CSR 서명됨"], ["skipping", "건너뜀"],
    ["role is unknown", "역할을 알 수 없음"], ["host(s)", "호스트"],
  ];
  return phrases.reduce((out, [en, ko]) => out.replaceAll(en, ko), text);
}
