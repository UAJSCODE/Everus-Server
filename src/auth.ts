import { createHash, createPublicKey, randomUUID, verify } from "node:crypto";

const seenNonces = new Map<string, number>();
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;

export function base64(value: unknown, maxBytes = 16_384): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxBytes * 2) {
    throw new Error("Invalid encoded value");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0 || bytes.length > maxBytes || bytes.toString("base64") !== value) {
    throw new Error("Invalid base64 value");
  }
  return value;
}

export function signedRegistrationPayload(deviceId: string, x25519: string, ed25519: string) {
  return Buffer.from(`register\n${deviceId}\n${x25519}\n${ed25519}`, "utf8");
}

export function signatureIsValid(edPublicKeyBase64: string, payload: Buffer, signatureBase64: string) {
  try {
    const key = createPublicKey({
      key: Buffer.from(edPublicKeyBase64, "base64"),
      format: "der",
      type: "spki",
    });
    return verify(null, payload, key, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}

export function signedActionPayload(fields: Array<string | number>) {
  return Buffer.from(fields.join("\n"), "utf8");
}

export function isTimestampValid(timestamp: number, now = Date.now()) {
  return Number.isSafeInteger(timestamp) && Math.abs(now - timestamp) <= MAX_CLOCK_SKEW_MS;
}

export function isNonceValid(deviceId: string, nonce: string, now = Date.now()) {
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return false;
  for (const [key, expiry] of seenNonces) {
    if (expiry < now) seenNonces.delete(key);
  }
  return !seenNonces.has(`${deviceId}:${nonce}`);
}

export function sha256Base64(value: string) {
  return createHash("sha256").update(Buffer.from(value, "base64")).digest("base64");
}

export function checkTimestampAndNonce(deviceId: string, timestamp: number, nonce: string) {
  const now = Date.now();
  if (!isTimestampValid(timestamp, now)) {
    throw new Error("Request timestamp expired");
  }
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) throw new Error("Invalid nonce");
  const key = `${deviceId}:${nonce}`;
  if (!isNonceValid(deviceId, nonce, now)) throw new Error("Request replay detected");
  seenNonces.set(key, now + MAX_CLOCK_SKEW_MS);
}

export function newNonce() {
  return randomUUID().replaceAll("-", "") + randomUUID().replaceAll("-", "");
}
