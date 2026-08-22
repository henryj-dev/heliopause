import { finishWrite, writeNeedsDialog, type WriteAnswer, type WriteSpec } from "./write-ask.ts";

export type WritePending = { spec: WriteSpec; resolve: (value: WriteAnswer | null) => void };

/**
 * One window for the things a write needs from a person: a warning, a
 * reason, a one-time code. The listing re-renders on every poll; text
 * typed into the table would be wiped. Cancel of a previous ask is the
 * same as the operator dismissing it.
 */
export function writeAsk() {
  let pending = $state<WritePending | null>(null);

  function ask(spec: WriteSpec): Promise<WriteAnswer | null> {
    if (!writeNeedsDialog(spec)) return Promise.resolve({ otp: "", reason: "" });
    return new Promise((resolve) => {
      pending?.resolve(null);
      pending = { spec, resolve };
    });
  }

  function submit(input: { reason: string; otp: string }): void {
    const held = pending;
    if (!held) return;
    const answer = finishWrite(input, held.spec);
    if (!answer) return;
    pending = null;
    held.resolve(answer);
  }

  function cancel(): void {
    const held = pending;
    pending = null;
    held?.resolve(null);
  }

  return {
    get pending() {
      return pending;
    },
    ask,
    submit,
    cancel,
  };
}
