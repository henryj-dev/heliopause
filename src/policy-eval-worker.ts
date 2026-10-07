// # The thread a policy module is evaluated in
//
// A policy module is a commit in another repository, and until #89's first step it ran in the
// renderer's own realm: it could replace `globalThis.Error`, poison `Object.prototype.toJSON`, spin
// forever, or throw from a timer after a good answer. `AGENTS.md` records eleven rounds of closing
// those one at a time, and the measurement that ends it — `docs/policy-evaluation-realm-design.md`
// §4-a — says a worker releases the module graph (+0.007 MB per evaluation against +0.559) while
// `vm` does not.
//
// So the module is evaluated here, in a thread of its own, and what crosses back is **text**.
//
// ## What this file must get right, and why each line is load-bearing
//
// §3-b measured three ways a module reaches the parent without touching a single global. Each is one
// line here, and the order is the content of two of them:
//
//   ① `parentPort` is not the result path. A module can `import("node:worker_threads")` and post on
//      it, and it answers *first*. The parent therefore ignores `parentPort` entirely; it reads only
//      the dedicated port handed over below.
//   ② The port arrives in the first message, and is taken **before the policy module is imported**.
//      Passing it in `workerData` fails: `workerData` is readable, so the module reads the port and
//      posts on it. Importing first fails too, and worse — the module calls
//      `parentPort.once("message")`, takes the handover, and this code never gets a port at all.
//   ③ `MessagePort.prototype.postMessage` is captured before the policy module is imported. Left as
//      `reply.postMessage(...)`, the lookup happens at call time and a module that rewrote the
//      prototype intercepts the send.
//
// ⚠️ "Before any import" would be wrong: this file's own static imports are hoisted and run before
// anything below. They are this repository's modules, and the capture only has to precede the
// **dynamic** import of the policy module, which it does. Saying it the loose way invites someone to
// "fix" the order and break ②.
import { parentPort, workerData, MessagePort } from "node:worker_threads";
import { pathToFileURL } from "node:url";
import { collectModuleFacts } from "./policy-source.ts";
import type { ScreenSite } from "./policy-screen.ts";

// ③ — captured here, at the top of this module's body, which is after this file's static imports and
// before the dynamic import below.
//
// 🔴 **The method alone was not enough, and the first version shipped that way.** It captured
// `postMessage` and called it as `send.call(reply, …)` — and `.call` is looked up on
// `Function.prototype` at call time. A module that replaced `Function.prototype.call` intercepted the
// send and posted a complete forged payload, which the parent served with a 200 and logged as
// "verified" (measured; an independent review found the route). `apply` is captured with the method,
// and the call goes through it, so nothing between here and the port is looked up after the import.
//
// ⚠️ This is a patch on the measured route, not the boundary. Everything this thread sends is the
// module's to choose in principle, so the parent does not rely on it: the worker sends only what the
// module is entitled to say anyway (`site` and the resolver table), and the parent reads every other
// field from the checkout itself. @see `assemblePolicySource` in `./policy-source.ts`
//
// @see src/policy-render-service.test.ts "does not accept a result from a module that rewrites
// MessagePort.prototype.postMessage" and "… that replaces Function.prototype.call"
const send = MessagePort.prototype.postMessage;
const apply = Reflect.apply;

// The serialisation that produces the bytes. §2's requirement 1: the module's half is serialised in
// here, so nothing that cannot be written reaches the parent as a value. Captured for the same reason
// as ③.
const writeWire = JSON.stringify;

// `wire` is the module's half only — `{ site, services }` as JSON — and the parent checks the type of
// every field it reads. It is exported so the test and the parent describe one thing.
export type EvalReply =
  | { ok: true; wire: string }
  | { ok: false; message: string };

// ## The failure text, without trusting the module for it
//
// The message is read off a value the module threw, so it carries the same forgery and unreadability
// channels as any module-supplied string: `String(e)` can run a poisoned `toString`, and `e.message`
// can be a throwing getter. The renderer learned this in round ten (`asError`), and the fix there was
// to capture the constructor; here there is nothing to capture, because this realm belongs to the
// module. So the text is treated as untrusted input instead: one line, length-capped, and the parent
// never parses it.
//
// ⚠️ This does not make the text trustworthy — it makes it **readable without crashing**. A module
// can still put anything in it, including something shaped like a renderer log line.
//
// 🔴 **The newlines are deliberately left in.** The first version of this flattened them to spaces,
// and that defeated the parent's scrubber rather than helping it: `oneLine`
// (`src/log-scrub.ts`) replaces a newline with U+FFFD precisely so a forged
// `[policy-render] verified beta — 12 hosts` is *visible* as an injection instead of reading like
// this process's own output. Flattening to a space made the forgery clean, and
// `cannot be made to forge a log line by a policy module` went red. One scrubber, on the parent's
// side, at the point of printing.
function failureText(thrown: unknown): string {
  let text: string;
  try {
    if (typeof thrown === "string") {
      text = thrown;
    } else if (thrown !== null && typeof thrown === "object" && typeof (thrown as { message?: unknown }).message === "string") {
      text = (thrown as { message: string }).message;
    } else {
      // ## A thrown non-error still has to name itself
      //
      // `throw undefined` and `throw 0` reach here, and the first version of this interpolated
      // `.message` and sent the literal text `undefined` — so the renderer's reason said nothing about
      // what happened and `the reason did not name the value that was thrown` went red. The parent's
      // `asError` used to supply this wording; the throw no longer crosses the thread, so the wording
      // has to be produced on this side.
      //
      // The same wording the parent's `asError` produced, so an operator reads one sentence whichever
      // side built it: `String(thrown)`, and `typeof` only when that coercion throws (a poisoned
      // `toString`, `Symbol.toPrimitive`, `Object.create(null)`). A second version of this prefixed
      // `typeof` always and printed `a object: null` for `throw null` — typeof says "object" for null,
      // so the prefix was wrong on exactly the value the test pins.
      let described: string;
      try {
        described = String(thrown).slice(0, 200);
      } catch {
        described = `a ${typeof thrown} that cannot be described`;
      }
      text = `policy module threw a non-error value: ${described}`;
    }
  } catch {
    text = "(the module's error could not be read)";
  }
  if (typeof text !== "string") text = "(the module's error was not text)";
  // Capped, because this crosses a channel and is printed. The cap is not a scrub.
  return text.slice(0, 2_000);
}

// ② — the port, before the import. `parentPort` is non-null in a worker; the cast is the narrowing
// Node's types do not do for us.
const port = parentPort as NonNullable<typeof parentPort>;

const handover: { reply?: MessagePort } = await new Promise((resolve) => {
  port.once("message", (m: { reply?: MessagePort }) => resolve(m));
});
const reply = handover.reply;
if (!(reply instanceof MessagePort)) {
  // Nothing to answer on. Exiting non-zero is the only signal left, and the parent treats a worker
  // that exits without a result as that site's 503 (§3-a, decision 8).
  process.exit(3);
}

// Everything above runs before the module. Everything below is in its reach.
const task = workerData as { sitePath: string };

try {
  // ## No `?v=` and no child-version hook
  //
  // Both exist to defeat the module registry: ES modules are keyed by URL and never evicted, so the
  // renderer minted a fresh query per evaluation and (#59) versioned the children too, or a changed
  // `policies.json` went unread while the generation moved.
  //
  // A worker starts with an **empty registry** and is terminated after one evaluation, so there is
  // nothing to evict and nothing to defeat. The parent still computes the stamp — it is the cache key
  // and it decides *whether* to evaluate — but it no longer has to appear in a URL.
  //
  // @see policy-eval-worker.test.ts "a changed file the module imports is read on the next evaluation"
  const mod = (await import(pathToFileURL(task.sitePath).href)) as { site?: ScreenSite };
  if (!mod.site) throw new Error(`${task.sitePath} does not export \`site\``);

  // The zone check is **not** here. It reads `site.hosts[].id`, and in this thread every prototype it
  // touches belongs to the module — a getter or a replaced `Array.prototype` makes it pass. The parent
  // runs it on the parsed wire instead, where the values are data.
  //
  // Nor is anything the renderer reads from disk: `label`, `siteName`, `repo`, `head`, `files` and
  // `build` are filled in by the parent. Only the module's own half crosses.
  // @see bin/heliopause-policy-render.ts, and the decision note in docs/policy-eval-worker-notes.md
  apply(send, reply, [{ ok: true, wire: writeWire(collectModuleFacts(mod.site)) } satisfies EvalReply]);
} catch (thrown) {
  apply(send, reply, [{ ok: false, message: failureText(thrown) } satisfies EvalReply]);
}
