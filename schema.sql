CREATE TABLE IF NOT EXISTS devices (
    device_id UUID PRIMARY KEY,
    ed25519_public_key TEXT NOT NULL,
    x25519_public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pairing_requests (
    request_id UUID PRIMARY KEY,
    from_device UUID NOT NULL REFERENCES devices(device_id),
    to_device UUID NOT NULL REFERENCES devices(device_id),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'COMPLETED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    responded_at TIMESTAMPTZ,
    CHECK (from_device <> to_device)
);
CREATE INDEX IF NOT EXISTS pairing_target_pending_idx
    ON pairing_requests(to_device, status, expires_at);

CREATE TABLE IF NOT EXISTS relationships (
    relationship_id UUID PRIMARY KEY,
    device_a UUID NOT NULL REFERENCES devices(device_id),
    device_b UUID NOT NULL REFERENCES devices(device_id),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'ACCEPTED', 'REJECTED', 'EXPIRED', 'COMPLETED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (device_a < device_b),
    UNIQUE (device_a, device_b)
);

CREATE TABLE IF NOT EXISTS messages (
    message_id UUID PRIMARY KEY,
    relationship_id UUID NOT NULL REFERENCES relationships(relationship_id),
    from_device UUID NOT NULL REFERENCES devices(device_id),
    to_device UUID NOT NULL REFERENCES devices(device_id),
    iv_base64 TEXT NOT NULL,
    ciphertext_base64 TEXT NOT NULL,
    signature_base64 TEXT NOT NULL,
    client_timestamp BIGINT NOT NULL,
    client_nonce TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS messages_recipient_delivery_idx
    ON messages(to_device, delivered_at, created_at);

CREATE TABLE IF NOT EXISTS media_transfers (
    transfer_id UUID PRIMARY KEY,
    message_id UUID NOT NULL REFERENCES messages(message_id),
    sender_device_id UUID NOT NULL REFERENCES devices(device_id),
    receiver_device_id UUID NOT NULL REFERENCES devices(device_id),
    filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    object_key TEXT NOT NULL,
    bucket TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'UPLOADING', 'COMPLETED', 'FAILED', 'EXPIRED')),
    upload_progress INTEGER DEFAULT 0 CHECK (upload_progress >= 0 AND upload_progress <= 100),
    checksum TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS media_transfers_receiver_idx
    ON media_transfers(receiver_device_id, status, expires_at);
CREATE INDEX IF NOT EXISTS media_transfers_message_idx
    ON media_transfers(message_id);