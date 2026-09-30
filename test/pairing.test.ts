import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { randomBytes, randomUUID, sign } from "node:crypto";
import { WebSocket } from "ws";
import { PGlite } from "@electric-sql/pglite";
import { createApp } from "../src/app.ts";
import { signatureIsValid, signedActionPayload, signedRegistrationPayload } from "../src/auth.ts";

const db = new PGlite();
const schema = await readFile(fileURLToPath(new URL("../schema.sql", import.meta.url)), "utf8");
await db.exec(schema);
const { app } = await createApp({ db, pairingTtlSeconds: 3 });
let baseUrl = "";
let wsUrl = "";
const devices = [createDevice(), createDevice()];

function createDevice() {
  const keys = cryptoModule.generateKeyPairSync("ed25519");
  const x25519 = cryptoModule.generateKeyPairSync("x25519");
  const edPublic = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const xPublic = x25519.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const deviceId = randomUUID();
  return {
    deviceId,
    edPublic,
    xPublic,
    sign(payload: Buffer) {
      return sign(null, payload, keys.privateKey).toString("base64");
    },
  };
}

import * as cryptoModule from "node:crypto";

async function register(device: ReturnType<typeof createDevice>) {
  const response = await fetch(`${baseUrl}/devices/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      deviceId: device.deviceId,
      ed25519PublicKey: device.edPublic,
      x25519PublicKey: device.xPublic,
      signature: device.sign(signedRegistrationPayload(device.deviceId, device.xPublic, device.edPublic)),
    }),
  });
  assert.equal(response.status, 200);
}

async function signedPost(device: ReturnType<typeof createDevice>, path: string, body: Record<string, unknown>, fields: Array<string | number>) {
  const timestamp = Date.now();
  const nonce = randomBytes(24).toString("base64url");
  const payload = signedActionPayload([...fields, timestamp, nonce]);
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ...body,
      timestamp,
      nonce,
      signature: device.sign(payload),
    }),
  });
}

async function connect(device: ReturnType<typeof createDevice>) {
  const timestamp = Date.now();
  const nonce = randomBytes(24).toString("base64url");
  const signature = device.sign(signedActionPayload(["ws", device.deviceId, timestamp, nonce]));
  const socket = new WebSocket(`${wsUrl}/ws?deviceId=${device.deviceId}&timestamp=${timestamp}&nonce=${nonce}&signature=${encodeURIComponent(signature)}`);
  const queue: Array<Record<string, unknown>> = [];
  const waiters: Array<(event: Record<string, unknown>) => void> = [];
  let resolveReady!: () => void;
  let rejectReady!: (error: Error) => void;
  const authenticated = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  socket.on("message", (data) => {
    const event = JSON.parse(data.toString()) as Record<string, unknown>;
    if (event.type === "connection.ready") {
      resolveReady();
      return;
    }
    const waiter = waiters.shift();
    if (waiter) waiter(event);
    else queue.push(event);
  });
  socket.once("error", rejectReady);
  await new Promise<void>((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  await Promise.race([
    authenticated,
    new Promise<never>((_, reject) => {
      const timeout = setTimeout(() => reject(new Error("WebSocket authentication acknowledgement timed out")), 5_000);
      timeout.unref();
    }),
  ]);
  return {
    socket,
    next() {
      const queued = queue.shift();
      if (queued) return Promise.resolve(queued);
      return new Promise<Record<string, unknown>>((resolve) => waiters.push(resolve));
    },
  };
}

before(async () => {
  const address = await app.listen({ host: "127.0.0.1", port: 0 });
  baseUrl = address;
  wsUrl = address.replace(/^http/, "ws");
});

after(async () => {
  await app.close();
  await db.close();
});

test("authenticated registration, realtime request/acceptance, and ciphertext routing", async () => {
  await register(devices[0]);
  await register(devices[1]);
  const receiver = await connect(devices[1]);
  const sender = await connect(devices[0]);
  const requestId = randomUUID();
  const requestTime = Date.now();
  const requestNonce = randomBytes(24).toString("base64url");
  const requestSignature = devices[0].sign(signedActionPayload([
    "pair-request", requestId, devices[0].deviceId, devices[1].deviceId, requestTime, requestNonce,
  ]));
  const requestResponse = await fetch(`${baseUrl}/pairing/request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requestId,
      fromDeviceId: devices[0].deviceId,
      targetDeviceId: devices[1].deviceId,
      timestamp: requestTime,
      nonce: requestNonce,
      signature: requestSignature,
    }),
  });
  assert.equal(requestResponse.status, 202);
  const incoming = await receiver.next();
  assert.equal(incoming.type, "pairing.request");
  assert.equal(incoming.fromDeviceId, devices[0].deviceId);

  const responseTimestamp = Date.now();
  const responseNonce = randomBytes(24).toString("base64url");
  const responseSignature = devices[1].sign(signedActionPayload([
    "pair-response", requestId, devices[1].deviceId, "ACCEPT", responseTimestamp, responseNonce,
  ]));
  const acceptedResponse = await fetch(`${baseUrl}/pairing/respond`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requestId,
      responderDeviceId: devices[1].deviceId,
      action: "ACCEPT",
      timestamp: responseTimestamp,
      nonce: responseNonce,
      signature: responseSignature,
    }),
  });
  assert.equal(acceptedResponse.status, 200);
  const accepted = await sender.next();
  assert.equal(accepted.type, "pairing.accepted");
  assert.equal(accepted.status, "COMPLETED");

  const relationship = await db.query(
    "SELECT status FROM relationships WHERE status='COMPLETED'",
  );
  assert.equal(relationship.rows.length, 1);

  const messageId = randomUUID();
  const timestamp = Date.now();
  const nonce = randomBytes(24).toString("base64url");
  const iv = randomBytes(12).toString("base64");
  // Deliberately opaque ciphertext: API and database only route/store this envelope.
  const ciphertext = randomBytes(48).toString("base64");
  const signature = devices[0].sign(signedActionPayload([
    "message", messageId, devices[0].deviceId, devices[1].deviceId, timestamp, nonce, iv, ciphertext,
  ]));
  const messageResponse = await fetch(`${baseUrl}/messages`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      messageId,
      fromDeviceId: devices[0].deviceId,
      targetDeviceId: devices[1].deviceId,
      timestamp,
      nonce,
      iv,
      ciphertext,
      signature,
    }),
  });
  assert.equal(messageResponse.status, 202);
  const delivered = await receiver.next();
  assert.equal(delivered.type, "message");
  assert.equal(delivered.ciphertext, ciphertext);
  const ackTimestamp = Date.now();
  const ackNonce = randomBytes(24).toString("base64url");
  const ackSignature = devices[1].sign(signedActionPayload([
    "message-ack", messageId, devices[1].deviceId, ackTimestamp, ackNonce,
  ]));
  const acknowledgement = await fetch(`${baseUrl}/messages/ack`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      messageId,
      receiverDeviceId: devices[1].deviceId,
      timestamp: ackTimestamp,
      nonce: ackNonce,
      signature: ackSignature,
    }),
  });
  assert.equal(acknowledgement.status, 200);
  const storedMessage = await db.query<{ delivered_at: string; ciphertext_base64: string }>(
    "SELECT delivered_at, ciphertext_base64 FROM messages WHERE message_id=$1",
    [messageId],
  );
  assert.ok(storedMessage.rows[0]?.delivered_at);
  assert.equal(storedMessage.rows[0]?.ciphertext_base64, ciphertext);

  sender.socket.close();
  receiver.socket.close();
});

test("Android WebSocket Ed25519 authentication contract uses identical UTF-8 payload bytes", async () => {
  const device = createDevice();
  await register(device);

  const timestamp = Date.now();
  const nonce = randomBytes(32).toString("hex");
  const androidPayload = Buffer.from(
    `ws\n${device.deviceId}\n${timestamp}\n${nonce}`,
    "utf8",
  );
  const serverPayload = signedActionPayload(["ws", device.deviceId, timestamp, nonce]);
  assert.deepEqual(serverPayload, androidPayload);

  const signature = device.sign(androidPayload);
  assert.equal(signatureIsValid(device.edPublic, serverPayload, signature), true);
  const stored = await db.query<{ ed25519_public_key: string }>(
    "SELECT ed25519_public_key FROM devices WHERE device_id=$1",
    [device.deviceId],
  );
  assert.equal(stored.rows[0]?.ed25519_public_key, device.edPublic);
});

test("rejects a replayed authenticated pairing request", async () => {
  const replaySource = createDevice();
  await register(replaySource);
  const requestId = randomUUID();
  const timestamp = Date.now();
  const nonce = randomBytes(24).toString("base64url");
  const signature = replaySource.sign(signedActionPayload([
    "pair-request", requestId, replaySource.deviceId, devices[1].deviceId, timestamp, nonce,
  ]));
  const body = {
    requestId,
    fromDeviceId: replaySource.deviceId,
    targetDeviceId: devices[1].deviceId,
    timestamp,
    nonce,
    signature,
  };
  const first = await fetch(`${baseUrl}/pairing/request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  assert.equal(first.status, 202);
  const replay = await fetch(`${baseUrl}/pairing/request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  assert.equal(replay.status, 400);
});
