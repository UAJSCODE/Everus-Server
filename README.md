# Everus signaling service

## Local emulator run

Requires Node.js 22.18+ (tested with Node 24.18). No PostgreSQL service is needed for local
development: PGlite runs PostgreSQL in-process and persists its database under `data/`.

```powershell
cd C:\ujascode.com\everus\everus-server
npm install
npm start
```

The server binds `0.0.0.0:8080`. The debug Android build uses
`http://10.0.2.2:8080/` so both Android emulators reach the host. Override this with
`EVERUS_DEBUG_API_BASE_URL` or Gradle property `everusDebugApiBaseUrl` when assembling.

Copy `.env.example` to `.env` to configure the server. To use a PostgreSQL service instead of
embedded PGlite, set `DATABASE_URL`; `schema.sql` is applied at startup. For production, place
the server behind HTTPS/WSS termination and configure a TLS-protected PostgreSQL connection.
Do not expose the local HTTP endpoint to untrusted networks.

## Protocol

- Device registration includes only the client-generated stable UUID and DER-encoded public keys.
  The device proves possession of its Ed25519 private key by signing the registration tuple.
- Pairing requests, responses, messages, and acknowledgements are Ed25519-signed and timestamped;
  one-time nonces are replay-checked.
- WebSocket connections sign the device ID, timestamp, and nonce. Pending pairing requests and
  undelivered encrypted messages are sent again after reconnection.
- Pairing state expires after `PAIRING_TTL_SECONDS` (180 seconds by default).
- Message bodies are AES-GCM ciphertext only. The service stores/routes the ciphertext, IV, and
  signatures; no message plaintext or device private key is sent to this service.
- The current Android chat key uses long-term X25519 agreement and HKDF. This is E2E encrypted but
  does not provide forward secrecy; perform an independent protocol/security review before
  production use.

## Verification

```powershell
npm test
npm exec tsc -- --noEmit
```
