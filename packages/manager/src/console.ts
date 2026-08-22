// Re-export. The implementation lives in `src/web-console.ts` so the published
// library and the manager image can serve `/app` without this workspace package.

export { CONSOLE_PREFIX, resolveWebRoot, serveConsole } from "../../../src/web-console.ts";
