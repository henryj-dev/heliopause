import adapter from "@sveltejs/adapter-static";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    // Under /app so the existing /fleet HTML console keeps answering.
    // adapter-node is rejected: TLS and client certificates stay on the
    // Node https listener, not inside Kit.
    paths: { base: "/app" },
    // The half of the CSP that only the build can write.
    //
    // Kit's built page starts with an inline module script, so `script-src 'self'` alone blanks the
    // console. Kit hashes that script at build time and emits the directive into a `<meta
    // http-equiv>` in the HTML; the rest of the policy is sent as a header by `serveConsole` in
    // `src/web-console.ts`, and the browser enforces the intersection of the two.
    //
    // Split this way on purpose: a hash cannot be written by hand in the server, and
    // `frame-ancestors` is **ignored** in a meta element — it only works as a header. So each
    // directive lives in the one place that can actually deliver it.
    csp: {
      mode: "hash",
      directives: {
        "script-src": ["self"],
      },
    },
    adapter: adapter({
      pages: "build",
      assets: "build",
      fallback: "index.html",
      precompress: false,
      strict: true,
    }),
  },
};

export default config;
