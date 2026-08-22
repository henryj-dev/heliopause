// Getting a one-time code from the person running the command.
//
// ## Why this is not just `--otp=123456`
//
// The flag exists, for scripts and for a terminal that cannot prompt. It is not the default because
// a code on the command line is written to shell history, and the history file outlives the code's
// thirty-second window by months. The IdP refuses a reused code — KeyStone stores the last accepted
// step — so a leaked code is not a standing key. What it is, is a record of an approval that somebody
// can read later, next to the plan hash it approved.
//
// A hidden prompt costs one keystroke more and leaves nothing behind.
//
// ## Why raw mode rather than readline
//
// Muting `readline` means assigning to `_writeToOutput`, which is an internal. This project has no
// runtime dependencies and would rather own twenty lines than reach into another module's private
// surface — the same reasoning as everywhere else here.
//
// ## Why the prompt goes to stderr
//
// So `heliopause-approve ... | jq` still works. The prompt is for the human; stdout is for the
// caller.

/** Thrown when there is no way to ask. Carries what to do instead, because the fix is a flag. */
export class NoPromptError extends Error {
  constructor(what: string) {
    super(
      `${what} needs a one-time code, and this terminal cannot ask for one (stdin is not a TTY).\n` +
        `Pass --otp=<code>, or set HELIOPAUSE_OTP, if you are running this from a script.`,
    );
  }
}

/**
 * Read a line from the terminal without echoing it.
 *
 * Backspace is handled because a mistyped digit with no echo is otherwise unrecoverable — the person
 * cannot see what they typed, so they cannot know how much to delete. Ctrl-C rejects rather than
 * killing the process, so the caller's own cleanup runs.
 */
export function readSecret(prompt: string, stdin = process.stdin, stderr = process.stderr): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!stdin.isTTY || typeof stdin.setRawMode !== "function") {
      reject(new NoPromptError("this action"));
      return;
    }
    stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    let typed = "";
    // 0 = ordinary text, 1 = just saw ESC, 2 = inside a CSI/SS3 sequence.
    //
    // Dropping the ESC byte alone is not enough, and that is the mistake worth naming: an arrow key
    // is `ESC [ A`, and `[` and `A` are ordinary printable characters. Filtering only on "is this a
    // control character" leaves `[A` in the code, which then fails to verify — and the failure reads
    // to the operator as the IdP rejecting a code they typed correctly.
    let escape = 0;
    const finish = (value: string | null, err?: Error) => {
      stdin.removeListener("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      stderr.write("\n");
      if (err) reject(err);
      else resolve(value ?? "");
    };
    const onData = (chunk: string) => {
      // A paste arrives as one chunk, so this iterates rather than switching on `chunk` itself.
      for (const ch of chunk) {
        if (escape === 2) {
          // Parameter and intermediate bytes run 0x20–0x3F; the final byte is 0x40–0x7E and ends it.
          if (ch >= "@" && ch <= "~") escape = 0;
          continue;
        }
        if (escape === 1) {
          if (ch === "[" || ch === "O") {
            escape = 2;
            continue;
          }
          // A bare Escape keypress. Fall through so this character is still handled normally rather
          // than swallowed — losing a digit here would be the same failure in a smaller form.
          escape = 0;
        }
        if (ch === "\u001b") {
          escape = 1;
          continue;
        }
        if (ch === "\r" || ch === "\n") return finish(typed);
        if (ch === "\u0003") return finish(null, new Error("cancelled"));
        if (ch === "\u007f" || ch === "\b") {
          typed = typed.slice(0, -1);
          continue;
        }
        // Anything else below 0x20 — a stray Ctrl-key, a bell — is dropped rather than stored. The
        // escape sequences that would survive this test are handled by the state machine above.
        if (ch >= " ") typed += ch;
      }
    };
    stdin.on("data", onData);
  });
}

/**
 * The one-time code for an action, from the flag, the environment, or the terminal.
 *
 * Order is deliberate: an explicit flag beats an environment variable that may be left over from a
 * previous shell, and both beat asking. Whitespace is stripped here rather than at the manager,
 * because a code read off a phone is often typed with a space in the middle.
 */
export async function otpFor(
  what: string,
  flag: string | undefined,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  const given = flag ?? env.HELIOPAUSE_OTP;
  if (given) return given.replace(/\s/g, "");
  if (!process.stdin.isTTY) throw new NoPromptError(what);
  const typed = await readSecret(`one-time code for ${what}: `);
  return typed.replace(/\s/g, "");
}
