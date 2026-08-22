/** Empty is cancel, not a code the IdP would refuse. */
export function readOtpInput(raw: string): string | null {
  const code = raw.trim();
  return code === "" ? null : code;
}

export function readReason(raw: string): string | null {
  const text = raw.trim();
  return text === "" ? null : text;
}

export interface WriteSpec {
  what: string;
  warning?: string;
  reason?: boolean;
  reasonLabel?: string;
  needsOtp: boolean;
}

export interface WriteAnswer {
  otp: string;
  reason: string;
}

export function writeNeedsDialog(spec: Pick<WriteSpec, "needsOtp" | "reason" | "warning">): boolean {
  return spec.needsOtp || spec.reason === true || (spec.warning !== undefined && spec.warning !== "");
}

export function writeIsReady(
  input: { reason: string; otp: string },
  spec: Pick<WriteSpec, "reason" | "needsOtp">,
): boolean {
  if (spec.reason && readReason(input.reason) === null) return false;
  if (spec.needsOtp && readOtpInput(input.otp) === null) return false;
  return true;
}

export function finishWrite(
  input: { reason: string; otp: string },
  spec: Pick<WriteSpec, "reason" | "needsOtp">,
): WriteAnswer | null {
  if (!writeIsReady(input, spec)) return null;
  return {
    otp: spec.needsOtp ? readOtpInput(input.otp) ?? "" : "",
    reason: spec.reason ? readReason(input.reason) ?? "" : "",
  };
}
