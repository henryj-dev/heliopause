export const CSRF_HEADER = "x-heliopause-csrf";

export function writeHeaders(csrf: string | null): Record<string, string> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (csrf) headers[CSRF_HEADER] = csrf;
  return headers;
}

export function tokenCreateBody(hostname: string, label: string, otp: string): string {
  return JSON.stringify({ hostname, label, otp });
}

export function otpBody(otp: string): string {
  return JSON.stringify({ otp });
}

export function csrRejectBody(reason: string, otp: string): string {
  return JSON.stringify({ reason, otp });
}

export function certUploadBody(certificatePem: string, caName: string, otp: string): string {
  return JSON.stringify({ certificatePem, caName, otp });
}

export function certRevokeBody(certificatePem: string, reason: string, otp: string): string {
  return JSON.stringify({ certificatePem, reason, otp });
}
