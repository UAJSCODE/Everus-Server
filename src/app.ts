import Fastify from "fastify";
import websocket from "@fastify/websocket";
import type { FastifyRequest } from "fastify";
import type { WebSocket } from "ws";
import { randomUUID } from "node:crypto";
import {
  base64,
  checkTimestampAndNonce,
  isNonceValid,
  isTimestampValid,
  signatureIsValid,
  signedActionPayload,
  signedRegistrationPayload,
} from "./auth.ts";
import { EventHub } from "./events.ts";
import type { Database } from "./db.ts";

type Device = { device_id: string; ed25519_public_key: string; x25519_public_key: string };
type ApiRequest = FastifyRequest<{ Body: Record<string, unknown> }>;
type ServerOptions = { db: Database; pairingTtlSeconds?: number; messageMaxBytes?: number };

function requiredString(value: unknown, name: string, maxLength = 512) {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new Error(`Invalid ${name}`);
  }
  return value;
}

function requiredUuid(value: unknown, name: string) {
  const result = requiredString(value, name, 36);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(result)) {
    throw new Error(`Invalid ${name}`);
  }
  return result.toLowerCase();
}

function signedBody(deviceId: string, body: Record<string, unknown>, fields: Array<string | number>) {
  const timestamp = Number(body.timestamp);
  const nonce = requiredString(body.nonce, "nonce", 128);
  const signature = base64(body.signature, 128);
  checkTimestampAndNonce(deviceId, timestamp, nonce);
  return { timestamp, nonce, signature, payload: signedActionPayload(fields) };
}

function requireSignature(device: Device | undefined, signature: string, payload: Buffer) {
  if (!device || !signatureIsValid(device.ed25519_public_key, payload, signature)) {
    throw new Error("Device authentication failed");
  }
}

export async function createApp({ db, pairingTtlSeconds = Number(process.env.PAIRING_TTL_SECONDS ?? 180), messageMaxBytes = Number(process.env.MESSAGE_MAX_BYTES ?? 65_536) }: ServerOptions) {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      serializers: {
        req(request) {
          return {
            method: request.method,
            url: request.url.split("?")[0],
            remoteAddress: request.socket.remoteAddress,
          };
        },
      },
    },
    bodyLimit: 256 * 1024,
  });
  const hub = new EventHub();
  await app.register(websocket);

  app.get("/health", async () => ({ status: "ok" }));

  app.post("/devices/register", async (request, reply) => {
    try {
      const body = request.body as Record<string, unknown>;
      const deviceId = requiredUuid(body.deviceId, "deviceId");
      const ed25519 = base64(body.ed25519PublicKey, 128);
      const x25519 = base64(body.x25519PublicKey, 128);
      const signature = base64(body.signature, 128);
      const payload = signedRegistrationPayload(deviceId, x25519, ed25519);
      if (!signatureIsValid(ed25519, payload, signature)) return reply.code(401).send({ error: "Invalid registration proof" });

      const existing = await db.query("SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id = $1", [deviceId]);
      if (existing.rows[0] && (existing.rows[0].ed25519_public_key !== ed25519 || existing.rows[0].x25519_public_key !== x25519)) {
        return reply.code(409).send({ error: "Device ID already belongs to another identity" });
      }
      await db.query(
        `INSERT INTO devices(device_id, ed25519_public_key, x25519_public_key, last_seen_at)
         VALUES ($1, $2, $3, now())
         ON CONFLICT (device_id) DO UPDATE SET last_seen_at = now()`,
        [deviceId, ed25519, x25519],
      );
      app.log.info({ event: "DEVICE_REGISTERED", deviceId });
      return { deviceId };
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid registration" });
    }
  });

  app.get("/ws", { websocket: true }, async (socket: WebSocket, request) => {
    const query = request.query as Record<string, unknown>;
    const deviceId = String(query.deviceId ?? "").toLowerCase();
    const timestamp = Number(query.timestamp);
    const nonce = String(query.nonce ?? "");
    const signature = String(query.signature ?? "");
    const correlationId = randomUUID();
    let deviceFound = false;
    let timestampValid = isTimestampValid(timestamp);
    let nonceValid = isNonceValid(deviceId, nonce);
    let signatureValid = false;
    let authPhase = "device_lookup";
    try {
      const deviceResult = await db.query(
        "SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id = $1",
        [deviceId],
      );
      const device = deviceResult.rows[0];
      deviceFound = Boolean(device);
      if (!device) throw new Error("Device is not registered");
      authPhase = "signature_validation";
      signatureValid = signatureIsValid(
        device.ed25519_public_key,
        signedActionPayload(["ws", deviceId, timestamp, nonce]),
        signature,
      );
      authPhase = "timestamp_nonce_validation";
      if (!timestampValid) throw new Error("Request timestamp expired");
      if (!nonceValid) throw new Error("Invalid or replayed nonce");
      checkTimestampAndNonce(deviceId, timestamp, nonce);
      if (!signatureValid) throw new Error("Device authentication failed");
      authPhase = "authenticated";
      hub.add(deviceId, socket);
      await db.query("UPDATE devices SET last_seen_at = now() WHERE device_id = $1", [deviceId]);
      await db.query(
        "UPDATE pairing_requests SET status='EXPIRED' WHERE to_device=$1 AND status='PENDING' AND expires_at <= now()",
        [deviceId],
      );
      const expiredFromThisDevice = await db.query(
        `UPDATE pairing_requests SET status='EXPIRED'
         WHERE from_device=$1 AND status='PENDING' AND expires_at <= now()
         RETURNING request_id, to_device`,
        [deviceId],
      );
      for (const row of expiredFromThisDevice.rows) {
        socket.send(JSON.stringify({ type: "pairing.expired", requestId: row.request_id }));
      }
      await db.query(
        `SELECT message_id, from_device, to_device, client_timestamp, client_nonce,
                iv_base64, ciphertext_base64, signature_base64
         FROM messages WHERE to_device=$1 AND delivered_at IS NULL ORDER BY created_at`,
        [deviceId],
      ).then(async (result) => {
        for (const row of result.rows) {
          socket.send(JSON.stringify({
            type: "message",
            messageId: row.message_id,
            fromDeviceId: row.from_device,
            targetDeviceId: row.to_device,
            timestamp: Number(row.client_timestamp),
            nonce: row.client_nonce,
            iv: row.iv_base64,
            ciphertext: row.ciphertext_base64,
            signature: row.signature_base64,
          }));
        }
      });
      app.log.info({ event: "WEBSOCKET_CONNECTED", deviceId });
      socket.send(JSON.stringify({ type: "connection.ready" }));

      const pending = await db.query(
        `SELECT p.request_id, p.from_device, p.created_at,
                d.ed25519_public_key, d.x25519_public_key
         FROM pairing_requests p JOIN devices d ON d.device_id = p.from_device
         WHERE p.to_device = $1 AND p.status = 'PENDING' AND p.expires_at > now()
         ORDER BY p.created_at`,
        [deviceId],
      );
      for (const row of pending.rows) {
        socket.send(JSON.stringify({
          type: "pairing.request",
          requestId: row.request_id,
          fromDeviceId: row.from_device,
          targetDeviceId: deviceId,
          createdAt: new Date(row.created_at).getTime(),
          ed25519PublicKey: row.ed25519_public_key,
          x25519PublicKey: row.x25519_public_key,
        }));
      }
      socket.on("close", () => {
        hub.remove(deviceId, socket);
        app.log.info({ event: "WEBSOCKET_DISCONNECTED", deviceId });
      });
      socket.on("error", () => {
        hub.remove(deviceId, socket);
      });
      socket.on("message", (data: Buffer) => {
        // Client-supplied socket events are not accepted; mutation uses signed HTTPS endpoints.
        app.log.warn({ event: "WEBSOCKET_UNEXPECTED_CLIENT_FRAME", deviceId, bytes: data.toString().length });
      });
    } catch (error) {
      app.log.warn({
        event: "WEBSOCKET_AUTH_FAILED",
        correlationId,
        phase: authPhase,
        AUTH_DEVICE_FOUND: deviceFound,
        AUTH_TIMESTAMP_VALID: timestampValid,
        AUTH_NONCE_VALID: nonceValid,
        AUTH_SIGNATURE_VALID: signatureValid,
        error: error.message,
      });
      socket.close(1008, "Authentication failed");
    }
  });

  app.post("/pairing/request", async (request: ApiRequest, reply) => {
    try {
      const body = request.body;
      const fromDevice = requiredUuid(body.fromDeviceId, "fromDeviceId");
      const toDevice = requiredUuid(body.targetDeviceId, "targetDeviceId");
      const requestId = requiredUuid(body.requestId, "requestId");
      const timestamp = Number(body.timestamp);
      const nonce = requiredString(body.nonce, "nonce", 128);
      const signature = base64(body.signature, 128);
      if (fromDevice === toDevice) return reply.code(400).send({ error: "Cannot pair a device with itself" });
      checkTimestampAndNonce(fromDevice, timestamp, nonce);
      const source = (await db.query("SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id = $1", [fromDevice])).rows[0];
      requireSignature(source, signature, signedActionPayload(["pair-request", requestId, fromDevice, toDevice, timestamp, nonce]));
      const target = (await db.query("SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id = $1", [toDevice])).rows[0];
      if (!target) return reply.code(404).send({ error: "Target device is not registered" });
      const relationship = await db.query("SELECT status FROM relationships WHERE (device_a = LEAST($1::uuid, $2::uuid) AND device_b = GREATEST($1::uuid, $2::uuid))", [fromDevice, toDevice]);
      if (relationship.rows[0]?.status === "COMPLETED") return reply.code(409).send({ error: "Devices are already paired" });
      const duplicate = await db.query(
        `SELECT request_id FROM pairing_requests WHERE from_device=$1 AND to_device=$2 AND status='PENDING' AND expires_at > now()`,
        [fromDevice, toDevice],
      );
      if (duplicate.rows[0]) return reply.code(409).send({ error: "A pairing request is already pending" });

      const expiresAt = new Date(Date.now() + pairingTtlSeconds * 1000);
      await db.query(
        `INSERT INTO pairing_requests(request_id, from_device, to_device, status, expires_at)
         VALUES ($1, $2, $3, 'PENDING', $4)`,
        [requestId, fromDevice, toDevice, expiresAt.toISOString()],
      );
      app.log.info({ event: "PAIRING_REQUEST_SENT", requestId, fromDevice, toDevice });
      const delivered = hub.send(toDevice, {
        type: "pairing.request",
        requestId,
        fromDeviceId: fromDevice,
        targetDeviceId: toDevice,
        createdAt: Date.now(),
        expiresAt: expiresAt.getTime(),
        ed25519PublicKey: source!.ed25519_public_key,
        x25519PublicKey: source!.x25519_public_key,
      });
      return reply.code(202).send({ requestId, status: "PENDING", delivered });
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid pairing request" });
    }
  });

  app.post("/pairing/respond", async (request: ApiRequest, reply) => {
    try {
      const body = request.body;
      const requestId = requiredUuid(body.requestId, "requestId");
      const responder = requiredUuid(body.responderDeviceId, "responderDeviceId");
      const action = requiredString(body.action, "action", 8).toUpperCase();
      if (!["ACCEPT", "REJECT"].includes(action)) return reply.code(400).send({ error: "Action must be ACCEPT or REJECT" });
      const timestamp = Number(body.timestamp);
      const nonce = requiredString(body.nonce, "nonce", 128);
      const signature = base64(body.signature, 128);
      checkTimestampAndNonce(responder, timestamp, nonce);
      const device = (await db.query("SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id = $1", [responder])).rows[0];
      requireSignature(device, signature, signedActionPayload(["pair-response", requestId, responder, action, timestamp, nonce]));
      const result = await db.query(
        `UPDATE pairing_requests SET status=$3, responded_at=now()
         WHERE request_id=$1 AND to_device=$2 AND status='PENDING' AND expires_at > now()
         RETURNING request_id, from_device, to_device`,
        [requestId, responder, action === "ACCEPT" ? "ACCEPTED" : "REJECTED"],
      );
      const row = result.rows[0];
      if (!row) return reply.code(409).send({ error: "Pairing request is missing, expired, or already answered" });
      if (action === "REJECT") {
        hub.send(row.from_device, { type: "pairing.rejected", requestId, fromDeviceId: responder });
        app.log.info({ event: "PAIRING_REJECTED", requestId, fromDevice: row.from_device, toDevice: responder });
        return { requestId, status: "REJECTED" };
      }

      const initiator = (await db.query("SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id=$1", [row.from_device])).rows[0]!;
      const [deviceA, deviceB] = [row.from_device, row.to_device].sort();
      const relationshipId = randomUUID();
      await db.query(
        `INSERT INTO relationships(relationship_id, device_a, device_b, status)
         VALUES ($1, $2, $3, 'COMPLETED')
         ON CONFLICT (device_a, device_b) DO UPDATE SET status='COMPLETED', updated_at=now()`,
        [relationshipId, deviceA, deviceB],
      );
      await db.query(
        "UPDATE pairing_requests SET status='COMPLETED' WHERE request_id=$1 AND status='ACCEPTED'",
        [requestId],
      );
      const event = {
        type: "pairing.accepted",
        requestId,
        relationshipId,
        fromDeviceId: responder,
        peerDeviceId: responder,
        ed25519PublicKey: device!.ed25519_public_key,
        x25519PublicKey: device!.x25519_public_key,
        status: "COMPLETED",
      };
      hub.send(row.from_device, event);
      app.log.info({ event: "PAIRING_ACCEPTED", requestId, fromDevice: row.from_device, toDevice: responder });
      return {
        requestId,
        relationshipId,
        status: "COMPLETED",
        peerDeviceId: row.from_device,
        ed25519PublicKey: initiator.ed25519_public_key,
        x25519PublicKey: initiator.x25519_public_key,
      };
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid pairing response" });
    }
  });

  app.post("/messages", async (request: ApiRequest, reply) => {
    try {
      const body = request.body;
      const messageId = requiredUuid(body.messageId, "messageId");
      const fromDevice = requiredUuid(body.fromDeviceId, "fromDeviceId");
      const toDevice = requiredUuid(body.targetDeviceId, "targetDeviceId");
      const timestamp = Number(body.timestamp);
      const nonce = requiredString(body.nonce, "nonce", 128);
      const iv = base64(body.iv, 12);
      const ciphertext = base64(body.ciphertext, messageMaxBytes);
      const signature = base64(body.signature, 128);
      if (Buffer.from(iv, "base64").length !== 12 || Buffer.from(ciphertext, "base64").length < 16 || Buffer.from(ciphertext, "base64").length > messageMaxBytes) {
        return reply.code(400).send({ error: "Invalid encrypted message envelope" });
      }
      checkTimestampAndNonce(fromDevice, timestamp, nonce);
      const source = (await db.query("SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id=$1", [fromDevice])).rows[0];
      requireSignature(source, signature, signedActionPayload(["message", messageId, fromDevice, toDevice, timestamp, nonce, iv, ciphertext]));
      const relationship = await db.query(
        `SELECT relationship_id FROM relationships WHERE device_a=LEAST($1::uuid,$2::uuid)
         AND device_b=GREATEST($1::uuid,$2::uuid) AND status='COMPLETED'`,
        [fromDevice, toDevice],
      );
      if (!relationship.rows[0]) return reply.code(403).send({ error: "No completed relationship exists" });
      await db.query(
        `INSERT INTO messages(message_id, relationship_id, from_device, to_device, iv_base64, ciphertext_base64, signature_base64, client_timestamp, client_nonce)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [messageId, relationship.rows[0].relationship_id, fromDevice, toDevice, iv, ciphertext, signature, timestamp, nonce],
      );
      const event = { type: "message", messageId, fromDeviceId: fromDevice, targetDeviceId: toDevice, timestamp, nonce, iv, ciphertext, signature };
      const delivered = hub.send(toDevice, event);
      app.log.info({ event: "MESSAGE_ROUTED", messageId, fromDevice, toDevice });
      return reply.code(202).send({ messageId, delivered });
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid message" });
    }
  });

  app.post("/messages/ack", async (request: ApiRequest, reply) => {
    try {
      const body = request.body;
      const messageId = requiredUuid(body.messageId, "messageId");
      const receiver = requiredUuid(body.receiverDeviceId, "receiverDeviceId");
      const timestamp = Number(body.timestamp);
      const nonce = requiredString(body.nonce, "nonce", 128);
      const signature = base64(body.signature, 128);
      checkTimestampAndNonce(receiver, timestamp, nonce);
      const device = (await db.query(
        "SELECT device_id, ed25519_public_key, x25519_public_key FROM devices WHERE device_id=$1",
        [receiver],
      )).rows[0];
      requireSignature(device, signature, signedActionPayload([
        "message-ack", messageId, receiver, timestamp, nonce,
      ]));
      const result = await db.query(
        `UPDATE messages SET delivered_at=COALESCE(delivered_at, now())
         WHERE message_id=$1 AND to_device=$2 RETURNING message_id`,
        [messageId, receiver],
      );
      if (!result.rows[0]) return reply.code(404).send({ error: "Message was not found for this device" });
      app.log.info({ event: "MESSAGE_DELIVERED", messageId, toDevice: receiver });
      return { messageId, delivered: true };
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid message acknowledgement" });
    }
  });

  // MEDIA TRANSFER ENDPOINTS
  app.post("/media/init", async (request: ApiRequest, reply) => {
    try {
      const body = request.body;
      const fromDeviceId = requiredUuid(body.senderDeviceId, "senderDeviceId");
      const toDeviceId = requiredUuid(body.receiverDeviceId, "receiverDeviceId");
      const filename = requiredString(body.filename, "filename", 255);
      const mimeType = requiredString(body.mimeType, "mimeType", 100);
      const fileSize = Number(body.fileSize);
      const transferId = randomUUID();

      // Validate sender and receiver are paired
      const relationship = await db.query(
        `SELECT status FROM relationships WHERE
         (device_a = LEAST($1::uuid, $2::uuid) AND device_b = GREATEST($1::uuid, $2::uuid))`,
        [fromDeviceId, toDeviceId]
      );
      if (!relationship.rows[0] || relationship.rows[0].status !== 'COMPLETED') {
        return reply.code(403).send({ error: "No completed relationship exists between devices" });
      }

      // Validate file size limits
      if (fileSize <= 0) {
        return reply.code(400).send({ error: "File size must be positive" });
      }
      if (fileSize > 100 * 1024 * 1024) { // 100MB limit
        return reply.code(400).send({ error: "File size exceeds maximum allowed size (100MB)" });
      }

      // Validate MIME type
      const allowedMimeTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'video/mp4', 'video/quicktime', 'video/x-msvideo',
        'application/pdf', 'text/plain', 'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      ];
      if (!allowedMimeTypes.includes(mimeType)) {
        return reply.code(400).send({ error: "Unsupported file type" });
      }

      // Generate object key for storage
      const objectKey = `${transferId}/${filename}`;

      // Determine bucket based on MIME type
      let bucket = 'everus-documents'; // default
      if (mimeType.startsWith('image/')) {
        bucket = 'everus-images';
      } else if (mimeType.startsWith('video/')) {
        bucket = 'everus-videos';
      }

      // Create media transfer record
      await db.query(
        `INSERT INTO media_transfers(
          transfer_id, message_id, sender_device_id, receiver_device_id,
          filename, mime_type, file_size, object_key, bucket, status, upload_progress, expires_at
        ) VALUES (
          $1, NULL, $2, $3, $4, $5, $6, $7, $8, 'PENDING', 0,
          NOW() + INTERVAL '1 hour'
        )`,
        [transferId, fromDeviceId, toDeviceId, filename, mimeType, fileSize, objectKey, bucket]
      );

      // In a real implementation with Supabase Storage, we would generate an upload URL here
      // For now, we'll return the transfer ID and let the client know they can upload via our chunked endpoint
      const uploadUrl = `/media/${transferId}/upload`;

      app.log.info({ event: "MEDIA_TRANSFER_INITIATED", transferId, fromDeviceId, toDeviceId, filename });
      return reply.code(201).send({
        transferId,
        uploadUrl,
        expiresAt: new Date(Date.now() + 3600 * 1000), // 1 hour from now
        maxChunkSize: 1024 * 1024 // 1MB chunks
      });
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid media transfer request" });
    }
  });

  app.post("/media/:transferId/upload", async (request: ApiRequest, reply) => {
    try {
      const transferId = requiredUuid(request.params.transferId, "transferId");
      const deviceId = requiredUuid(body.senderDeviceId, "senderDeviceId");

      // Get the transfer record
      const transferResult = await db.query(
        `SELECT * FROM media_transfers WHERE transfer_id = $1`,
        [transferId]
      );

      if (!transferResult.rows[0]) {
        return reply.code(404).send({ error: "Media transfer not found" });
      }

      const transfer = transferResult.rows[0];

      // Validate sender matches
      if (transfer.sender_device_id !== deviceId) {
        return reply.code(403).send({ error: "Unauthorized to upload to this transfer" });
      }

      // Validate transfer is in correct state
      if (transfer.status !== 'PENDING' && transfer.status !== 'UPLOADING') {
        return reply.code(400).send({ error: "Transfer is not in uploadable state" });
      }

      // In a real implementation, we would handle the file upload here
      // For now, we'll simulate by updating progress
      // The actual implementation would stream the upload to object storage

      // For this implementation, we'll assume the client sends the entire file in one request
      // but in reality, this should handle chunked uploads
      const body = request.body as Record<string, unknown>;
      const chunkData = base64(body.data, ""); // This would be the chunk data
      const chunkIndex = Number(body.chunkIndex);
      const totalChunks = Number(body.totalChunks);

      // Update progress
      const newProgress = Math.min(100, Math.floor(((chunkIndex + 1) / totalChunks) * 100));
      const newStatus = newProgress >= 100 ? 'COMPLETED' : 'UPLOADING';

      await db.query(
        `UPDATE media_transfers SET
         upload_progress = $1,
         status = $2,
         checksum = $3
         WHERE transfer_id = $4`,
        [newProgress, newStatus, body.checksum || null, transferId]
      );

      // If transfer is complete, we would notify the recipient via WebSocket
      // In a full implementation, we'd create a message record and send a WebSocket event
      if (newStatus === 'COMPLETED') {
        // Create a placeholder message record - in reality, this would contain encrypted metadata
        const messageId = randomUUID();
        await db.query(
          `INSERT INTO media_transfers(message_id) VALUES ($1) WHERE transfer_id = $2`,
          [messageId, transferId]
        );

        // Notify recipient via WebSocket
        hub.send(transfer.receiver_device_id, {
          type: "media.transfer.completed",
          transferId,
          messageId,
          senderDeviceId: transfer.sender_device_id,
          filename: transfer.filename,
          mimeType: transfer.mimeType,
          fileSize: transfer.file_size
        });

        app.log.info({ event: "MEDIA_TRANSFER_COMPLETED", transferId, messageId });
      }

      return reply.code(200).send({
        success: true,
        uploadProgress: newProgress,
        status: newStatus
      });
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid upload request" });
    }
  });

  app.get("/media/:transferId/download", async (request: ApiRequest, reply) => {
    try {
      const transferId = requiredUuid(request.params.transferId, "transferId");
      const deviceId = requiredUuid(body.receiverDeviceId, "receiverDeviceId");

      // Get the transfer record
      const transferResult = await db.query(
        `SELECT * FROM media_transfers WHERE transfer_id = $1`,
        [transferId]
      );

      if (!transferResult.rows[0]) {
        return reply.code(404).send({ error: "Media transfer not found" });
      }

      const transfer = transferResult.rows[0];

      // Validate receiver matches
      if (transfer.receiver_device_id !== deviceId) {
        return reply.code(403).send({ error: "Unauthorized to download from this transfer" });
      }

      // Validate transfer is completed
      if (transfer.status !== 'COMPLETED') {
        return reply.code(400).send({ error: "Transfer is not yet complete" });
      }

      // Validate not expired
      const expiresAt = new Date(transfer.expires_at);
      if (expiresAt < new Date()) {
        return reply.code(410).send({ error: "Media transfer has expired" });
      }

      // In a real implementation with Supabase Storage, we would generate a download URL here
      // For now, we'll return the metadata needed to construct the download
      const downloadUrl = `/media/storage/${transfer.bucket}/${transfer.objectKey}`;

      app.log.info({ event: "MEDIA_TRANSFER_DOWNLOAD_AUTHORIZED", transferId, deviceId });
      return reply.code(200).send({
        downloadUrl,
        expiresAt: transfer.expires_at,
        filename: transfer.filename,
        mimeType: transfer.mimeType,
        fileSize: transfer.file_size,
        checksum: transfer.checksum
      });
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid download request" });
    }
  });

  app.get("/media/:transferId", async (request: ApiRequest, reply) => {
    try {
      const transferId = requiredUuid(request.params.transferId, "transferId");
      const deviceId = requiredUuid(body.senderDeviceId, "senderDeviceId");

      // Get the transfer record
      const transferResult = await db.query(
        `SELECT * FROM media_transfers WHERE transfer_id = $1`,
        [transferId]
      );

      if (!transferResult.rows[0]) {
        return reply.code(404).send({ error: "Media transfer not found" });
      }

      const transfer = transferResult.rows[0];

      // Validate sender matches (for status checks) or receiver (for download prep)
      if (transfer.sender_device_id !== deviceId && transfer.receiver_device_id !== deviceId) {
        return reply.code(403).send({ error: "Unauthorized to access this transfer" });
      }

      app.log.info({ event: "MEDIA_TRANSFER_STATUS_QUERIED", transferId, deviceId });
      return reply.code(200).send({
        transferId,
        status: transfer.status,
        uploadProgress: transfer.upload_progress,
        filename: transfer.filename,
        mimeType: transfer.mimeType,
        fileSize: transfer.file_size,
        objectKey: transfer.object_key,
        bucket: transfer.bucket,
        checksum: transfer.checksum,
        createdAt: transfer.created_at,
        expiresAt: transfer.expires_at
      });
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Invalid status request" });
    }
  });

  const expiryTimer = setInterval(async () => {
    try {
      const expired = await db.query(
        `UPDATE pairing_requests SET status='EXPIRED'
         WHERE status='PENDING' AND expires_at <= now()
         RETURNING request_id, from_device, to_device`,
      );
      for (const row of expired.rows) {
        const event = { type: "pairing.expired", requestId: row.request_id };
        hub.send(row.from_device, event);
        hub.send(row.to_device, event);
        app.log.info({ event: "PAIRING_EXPIRED", requestId: row.request_id });
      }
    } catch {
      app.log.error({ event: "PAIRING_EXPIRY_SWEEP_FAILED" });
    }
  }, 5_000);
  expiryTimer.unref();
  app.addHook("onClose", async () => clearInterval(expiryTimer));

  app.setErrorHandler((error: Error & { statusCode?: number }, _request, reply) => {
    app.log.error({ event: "REQUEST_FAILED", statusCode: error.statusCode });
    reply.code(error.statusCode ?? 500).send({ error: "Request failed" });
  });

  return { app, hub, db };
}