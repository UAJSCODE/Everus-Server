# Everus Server

Backend signaling and communication service for **Everus**, a private
Android device-to-device communication application.

The server provides device registration, trusted-device pairing,
realtime WebSocket signaling, encrypted message routing, acknowledgement
handling, and persistence. Sensitive message content remains encrypted
on the client side; the server routes encrypted payloads rather than
receiving plaintext message bodies.

------------------------------------------------------------------------

## Table of Contents

-   [Overview](#overview)
-   [Architecture](#architecture)
-   [Technology Stack](#technology-stack)
-   [Production Deployment](#production-deployment)
-   [Local Development](#local-development)
-   [Environment Configuration](#environment-configuration)
-   [Database](#database)
-   [Server Endpoints](#server-endpoints)
-   [Device Identity](#device-identity)
-   [Pairing Protocol](#pairing-protocol)
-   [WebSocket Protocol](#websocket-protocol)
-   [Messaging](#messaging)
-   [Encryption and Security](#encryption-and-security)
-   [Replay Protection](#replay-protection)
-   [Persistence and Recovery](#persistence-and-recovery)
-   [Health Checks](#health-checks)
-   [Testing](#testing)
-   [Project Structure](#project-structure)
-   [Deployment Configuration](#deployment-configuration)
-   [Security Rules](#security-rules)
-   [Development Workflow](#development-workflow)
-   [Known Security Limitations](#known-security-limitations)
-   [Roadmap](#roadmap)
-   [License](#license)

------------------------------------------------------------------------

# Overview

Everus Server is the backend service for the Everus Android application.

Its primary responsibility is to provide a trusted communication and
signaling layer between paired Everus devices.

The server is designed around the following principle:

> **The server should coordinate trusted devices without becoming the
> holder of message plaintext or device private keys.**

The service handles:

-   Device registration
-   Public-key registration
-   Device authentication
-   Pairing requests
-   Pairing responses
-   Relationship state
-   WebSocket connections
-   Realtime message delivery
-   Message acknowledgements
-   Pending-message delivery after reconnect
-   Encrypted message persistence
-   Health checks

------------------------------------------------------------------------

# Architecture

``` text
                    Everus Android Device A
                              |
                              |
                       HTTPS / WSS
                              |
                              v
                  +-----------------------+
                  |     Everus Server     |
                  |                       |
                  |  Fastify HTTP API     |
                  |  WebSocket Server     |
                  |  Authentication       |
                  |  Pairing              |
                  |  Message Routing      |
                  +-----------+-----------+
                              |
                              v
                    +-------------------+
                    |    PostgreSQL     |
                    |   / Supabase      |
                    +-------------------+

                              ^
                              |
                       HTTPS / WSS
                              |
                    Everus Android Device B
```

For local development, PGlite can run PostgreSQL-compatible storage
inside the Node.js process.

For production, the service uses PostgreSQL through the configured
`DATABASE_URL`.

------------------------------------------------------------------------

# Technology Stack

## Runtime

-   Node.js 22.18+
-   Tested with Node.js 24.18

## Backend

-   TypeScript
-   Fastify
-   WebSocket
-   PostgreSQL
-   PGlite

## Database

-   PostgreSQL
-   Supabase PostgreSQL for production
-   PGlite for local development

## Cryptography / Protocol

-   Ed25519
-   X25519
-   HKDF
-   AES-GCM
-   Signed timestamps
-   One-time nonces
-   Replay protection

------------------------------------------------------------------------

# Production Deployment

Current production service:

``` text
https://everus-server.onrender.com/
```

WebSocket endpoint:

``` text
wss://everus-server.onrender.com/ws
```

Health endpoint:

``` text
https://everus-server.onrender.com/health
```

The production service is deployed on Render and uses a
PostgreSQL-compatible production database configuration.

Production environment variables include:

``` text
DATABASE_URL=<Supabase PostgreSQL connection string>
HOST=0.0.0.0
NODE_ENV=production
```

### Production requirements

The production deployment must provide:

-   HTTPS
-   WSS
-   TLS-protected PostgreSQL connection
-   Secure environment variables
-   No committed credentials
-   Database migrations/schema initialization
-   Health monitoring

------------------------------------------------------------------------

# Local Development

## Requirements

Install:

-   Node.js 22.18+
-   npm

Node.js 24.18 is the currently tested development version.

Check:

``` powershell
node --version
npm --version
```

## Clone

``` powershell
git clone https://github.com/UAJSCODE/Everus-Server.git
cd Everus-Server
```

## Install dependencies

``` powershell
npm install
```

## Start server

``` powershell
npm start
```

The local server binds to:

``` text
0.0.0.0:8080
```

Local HTTP base URL:

``` text
http://localhost:8080/
```

Android emulator URL:

``` text
http://10.0.2.2:8080/
```

The Android debug build can override the backend URL through:

``` text
EVERUS_DEBUG_API_BASE_URL
```

or the Gradle property:

``` text
everusDebugApiBaseUrl
```

------------------------------------------------------------------------

# Environment Configuration

Copy the example environment file:

``` powershell
Copy-Item .env.example .env
```

Example:

``` env
HOST=0.0.0.0
PORT=8080
NODE_ENV=development
DATABASE_URL=
PAIRING_TTL_SECONDS=180
```

The exact supported variables should always follow `.env.example` and
the server configuration.

## PostgreSQL

If `DATABASE_URL` is not provided for local development, PGlite can
provide the local PostgreSQL-compatible database.

If `DATABASE_URL` is configured, the server uses the external PostgreSQL
database.

Production should use a TLS-protected PostgreSQL connection.

------------------------------------------------------------------------

# Database

The backend uses PostgreSQL-compatible storage.

Local development can use:

``` text
PGlite
```

Production uses:

``` text
Supabase PostgreSQL
```

The database schema is initialized from:

``` text
schema.sql
```

The service stores server-side coordination data such as:

-   Devices
-   Pairing requests
-   Relationships
-   Encrypted messages

The database must not be used to store plaintext private keys.

------------------------------------------------------------------------

# Server Endpoints

The exact route list should be kept synchronized with the current
Fastify route registration.

The primary service interfaces include:

``` text
GET     /health
```

Device registration/authentication:

``` text
POST    /devices
```

Pairing:

``` text
POST    /pairing/requests
...
```

Messaging:

``` text
...
```

Message deletion:

``` text
DELETE  /messages/:messageId
```

WebSocket:

``` text
GET     /ws
```

> The backend source is the authoritative definition of the complete
> route list. Do not document an endpoint here as supported unless it
> exists in the current server implementation.

------------------------------------------------------------------------

# Device Identity

Everus does not use a conventional username/password account model for
device communication.

Device registration includes:

-   Client-generated stable UUID
-   DER-encoded public keys
-   Cryptographic proof of private-key possession

The client proves possession of its Ed25519 private key by signing the
registration data.

The private key remains on the client and is never sent to the server.

Conceptually:

``` text
Android Device
    |
    +-- Device UUID
    |
    +-- Ed25519 Public Key
    |
    +-- X25519 Public Key
    |
    +-- Ed25519 Signature
    |
    v
Everus Server
```

The server stores public identity information required for
authentication and routing.

------------------------------------------------------------------------

# Pairing Protocol

Pairing creates a trusted relationship between two devices.

General flow:

``` text
Device A
   |
   | Pairing Request
   | signed + timestamp + nonce
   v
Everus Server
   |
   | Pairing Request
   v
Device B
   |
   | Accept / Decline
   | signed + timestamp + nonce
   v
Everus Server
   |
   | Relationship State
   v
Device A
```

## Pairing Expiration

Pairing requests are temporary.

Default:

``` text
PAIRING_TTL_SECONDS=180
```

The Android client may display its own user-facing countdown according
to the application's pairing UX.

The server remains authoritative for request validity and expiration.

------------------------------------------------------------------------

# WebSocket Protocol

WebSocket communication is used for realtime delivery.

Production:

``` text
wss://everus-server.onrender.com/ws
```

Local:

``` text
ws://localhost:8080/ws
```

Android emulator:

``` text
ws://10.0.2.2:8080/ws
```

WebSocket authentication includes signed device information.

The protocol signs:

-   Device ID
-   Timestamp
-   Nonce

The server validates the signature and replay-protection parameters
before accepting authenticated communication.

------------------------------------------------------------------------

# Messaging

Everus messaging is designed around encrypted payloads.

The server routes encrypted message data rather than message plaintext.

A message can contain:

``` text
Message
├── message ID
├── sender device
├── recipient device
├── ciphertext
├── IV / nonce
├── signature
├── timestamp
└── delivery state
```

The server may persist an encrypted message while the recipient is
offline.

When the recipient reconnects, pending undelivered encrypted messages
can be delivered again.

The server does not require access to the plaintext message body.

------------------------------------------------------------------------

# Encryption and Security

## Message Encryption

Message bodies are stored/routed as AES-GCM ciphertext.

The server handles encrypted payloads, IVs, signatures, and routing
metadata.

The server does not receive:

``` text
Message plaintext
Device private keys
```

## Device Authentication

Ed25519 signatures are used for device authentication and protocol
messages.

## Key Agreement

The current Android chat implementation uses:

``` text
X25519
   ↓
HKDF
   ↓
Chat key
   ↓
AES-GCM encrypted messages
```

This provides end-to-end encryption for the current implementation.

However, the current chat-key design uses long-term X25519 agreement and
does **not** provide forward secrecy.

This limitation must be addressed before production deployment of a
high-security messaging system.

------------------------------------------------------------------------

# Replay Protection

Security-sensitive protocol messages include:

-   Timestamp
-   One-time nonce
-   Signature

The server performs replay checks on protocol messages.

Conceptually:

``` text
Incoming request
       |
       v
Validate timestamp
       |
       v
Validate nonce
       |
       v
Verify Ed25519 signature
       |
       v
Check relationship/device state
       |
       v
Accept request
```

Invalid, stale, duplicated, or unauthenticated messages should be
rejected.

------------------------------------------------------------------------

# Persistence and Recovery

The server persists information required for:

-   Device registration
-   Pairing state
-   Relationships
-   Pending encrypted messages
-   Message delivery state

When a WebSocket connection is interrupted:

``` text
Device disconnects
       |
       v
Messages remain pending
       |
       v
Device reconnects
       |
       v
Authenticated WebSocket
       |
       v
Pending encrypted messages delivered
```

The server must never reconstruct message plaintext during this process.

------------------------------------------------------------------------

# Health Checks

Use:

``` powershell
curl https://everus-server.onrender.com/health
```

Expected health response:

``` json
{
  "status": "ok"
}
```

For local development:

``` powershell
curl http://localhost:8080/health
```

A successful health response confirms that the HTTP server is running.
It does not by itself verify database connectivity, WebSocket
authentication, pairing, or message delivery.

------------------------------------------------------------------------

# Testing

## Unit Tests

Run:

``` powershell
npm test
```

## TypeScript Verification

Run:

``` powershell
npm exec tsc -- --noEmit
```

Recommended verification:

``` powershell
npm test
npm exec tsc -- --noEmit
```

Both should pass before deployment.

## Manual API Health Test

``` powershell
curl http://localhost:8080/health
```

## WebSocket Verification

Verify:

1.  Device registration
2.  WebSocket authentication
3.  Pairing request
4.  Pairing response
5.  Reconnection
6.  Pending message delivery
7.  Message acknowledgement
8.  Invalid signature rejection
9.  Replay rejection
10. Expired pairing rejection

------------------------------------------------------------------------

# Project Structure

Typical structure:

``` text
everus-server/
│
├── src/
│   ├── ...
│   ├── server.ts
│   ├── routes/
│   ├── websocket/
│   ├── auth/
│   ├── pairing/
│   ├── messaging/
│   └── ...
│
├── schema.sql
├── data/
│   └── ...
│
├── .env.example
├── .gitignore
├── package.json
├── package-lock.json
├── tsconfig.json
└── README.md
```

The exact source structure may evolve. The current codebase is the
authoritative source.

------------------------------------------------------------------------

# Deployment Configuration

## Render

The production service is intended to run as a Node.js web service.

Required production environment:

``` text
NODE_ENV=production
HOST=0.0.0.0
DATABASE_URL=<production PostgreSQL connection>
```

The server should listen on the port supplied by the deployment
environment when applicable.

Production should terminate external traffic using HTTPS/WSS.

## Database

Production PostgreSQL credentials must be supplied through environment
variables.

Never commit:

``` text
DATABASE_URL
database passwords
Supabase service-role keys
private API credentials
```

------------------------------------------------------------------------

# Security Rules

## Never commit secrets

Do not commit:

``` text
.env
.env.local
DATABASE_URL
Supabase service-role keys
private keys
passwords
tokens
production credentials
```

## Never expose private keys

The server must never receive:

``` text
Ed25519 private key
X25519 private key
Android Keystore private key
Backup encryption password
```

## Never log sensitive data

Do not log:

-   Message plaintext
-   Private keys
-   Passwords
-   Authentication secrets
-   Full encrypted payloads unless required for controlled debugging

## Production transport

Use:

``` text
HTTPS
WSS
TLS-protected PostgreSQL
```

Do not expose the development HTTP service directly to untrusted
networks.

------------------------------------------------------------------------

# Development Workflow

## 1. Install

``` powershell
npm install
```

## 2. Configure

``` powershell
Copy-Item .env.example .env
```

## 3. Run

``` powershell
npm start
```

## 4. Test

``` powershell
npm test
npm exec tsc -- --noEmit
```

## 5. Verify health

``` powershell
curl http://localhost:8080/health
```

## 6. Commit

Use focused commits:

``` powershell
git add .
git commit -m "Update server functionality"
```

Do not commit environment files or credentials.

------------------------------------------------------------------------

# Known Security Limitations

## No Forward Secrecy in Current Chat Key Design

The current Android chat key uses long-term X25519 agreement with HKDF.

It provides end-to-end encryption but does not currently provide forward
secrecy.

Before describing Everus as a production-grade secure messenger, the
protocol should undergo an independent cryptographic/security review
and, where required, move toward a ratcheting protocol such as a
correctly implemented Signal-style design.

## Device-Level Verification

Server-side unit/type checks do not prove complete end-to-end behavior.

The following must be verified with actual Android clients:

-   Pairing
-   Reconnection
-   Message delivery
-   Message acknowledgement
-   Offline delivery
-   Delete for everyone
-   Device disconnect/reconnect
-   Media transfer
-   Backup/restore integration

------------------------------------------------------------------------

# Roadmap

## Backend Foundation

-   [x] Node.js server
-   [x] Fastify HTTP service
-   [x] WebSocket service
-   [x] PostgreSQL-compatible persistence
-   [x] PGlite local development fallback
-   [x] Device registration
-   [x] Ed25519 authentication
-   [x] Pairing state
-   [x] Encrypted message routing
-   [x] Health endpoint

## Reliability

-   [x] Pending message delivery
-   [x] WebSocket reconnect handling
-   [x] Pairing expiration
-   [x] Replay protection
-   [ ] Comprehensive end-to-end device test suite
-   [ ] Production load testing
-   [ ] Failure/recovery testing

## Security

-   [x] Signed protocol messages
-   [x] Nonce/replay checks
-   [x] Encrypted message payloads
-   [x] No device private keys on server
-   [ ] Independent cryptographic protocol review
-   [ ] Forward secrecy / ratcheting protocol
-   [ ] Formal security audit

## Operations

-   [x] Render deployment
-   [x] Production PostgreSQL
-   [x] Health monitoring endpoint
-   [ ] Automated CI/CD verification
-   [ ] Production observability
-   [ ] Rate limiting review
-   [ ] Abuse/DoS protection review

------------------------------------------------------------------------

# Production Readiness Checklist

``` text
BUILD
[ ] npm test
[ ] TypeScript check
[ ] Production deployment succeeds

DATABASE
[ ] PostgreSQL connection verified
[ ] schema applied
[ ] connection pooling verified
[ ] backup/recovery strategy configured

HTTP
[ ] HTTPS enabled
[ ] /health works
[ ] Error handling verified

WEBSOCKET
[ ] WSS enabled
[ ] Authentication verified
[ ] Replay protection verified
[ ] Reconnect verified
[ ] Pending delivery verified

PAIRING
[ ] Request creation
[ ] Request expiration
[ ] Accept
[ ] Decline
[ ] Cancel
[ ] Duplicate protection
[ ] Relationship persistence

MESSAGING
[ ] Encrypted payload routing
[ ] Acknowledgements
[ ] Offline delivery
[ ] Reconnection
[ ] Delete for everyone

SECURITY
[ ] No plaintext message storage
[ ] No private keys on server
[ ] No secrets in Git
[ ] TLS
[ ] Rate limiting
[ ] Security review
[ ] Cryptographic protocol review

OPERATIONS
[ ] Logs reviewed
[ ] Monitoring
[ ] Database backup
[ ] Failure recovery
[ ] Deployment rollback plan
```

------------------------------------------------------------------------

# Repository

GitHub:

``` text
https://github.com/UAJSCODE/Everus-Server
```

Production server:

``` text
https://everus-server.onrender.com/
```

Production WebSocket:

``` text
wss://everus-server.onrender.com/ws
```

Android application:

``` text
https://github.com/UAJSCODE/Everus
```

------------------------------------------------------------------------

# License

No explicit open-source license is specified in the supplied server
README.

Until a license is added to the repository, treat the source as **all
rights reserved**.

------------------------------------------------------------------------

# Maintainer

**UJASCODE**

Everus Server is part of the UJASCODE Everus project.

------------------------------------------------------------------------

# Final Status

Everus Server provides the backend signaling and encrypted-message
routing foundation for the Everus Android application.

The current architecture supports:

``` text
Device Registration
        ↓
Cryptographic Authentication
        ↓
Device Pairing
        ↓
Trusted Relationship
        ↓
WebSocket Connection
        ↓
Encrypted Message Routing
        ↓
Acknowledgement / Reconnection
```

The server is intentionally designed so that message plaintext and
device private keys remain on the client side.

**Important:** The current Android chat-key design uses long-term
X25519 + HKDF and does not provide forward secrecy. This must be
independently reviewed before production use of Everus as a
high-security messaging application.
