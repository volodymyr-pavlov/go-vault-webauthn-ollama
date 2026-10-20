-- +goose Up
CREATE TABLE users
(
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_xid        BIGINT UNSIGNED NOT NULL,
    flags           BIGINT UNSIGNED NOT NULL DEFAULT 0,
    email           VARCHAR(255) NOT NULL,
    handle          VARBINARY(64) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    totp_ciphertext TEXT         NOT NULL,
    totp_last_step  BIGINT UNSIGNED NOT NULL DEFAULT 0,
    totp_failures   SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    created_at      DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY users_user_xid (user_xid),
    UNIQUE KEY users_email (email),
    UNIQUE KEY users_handle (handle)
);

CREATE TABLE passkeys
(
    id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    passkey_xid        BIGINT UNSIGNED NOT NULL,
    flags              BIGINT UNSIGNED NOT NULL DEFAULT 0,
    user_id            BIGINT UNSIGNED NOT NULL,
    credential_id      VARBINARY(1023) NOT NULL,
    public_key         BLOB         NOT NULL,
    attestation_type   VARCHAR(32)  NOT NULL DEFAULT '',
    attestation_format VARCHAR(32)  NOT NULL DEFAULT '',
    transports         TINYINT UNSIGNED NOT NULL DEFAULT 0,
    aaguid             VARBINARY(16) NOT NULL DEFAULT 0x00,
    sign_count         INT UNSIGNED NOT NULL DEFAULT 0,
    name               VARCHAR(64)  NOT NULL DEFAULT '',
    created_at         DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY passkeys_passkey_xid (passkey_xid),
    UNIQUE KEY passkeys_credential_id (credential_id),
    KEY                passkeys_user_id (user_id),
    CONSTRAINT passkeys_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE recovery_codes
(
    id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    recovery_code_xid BIGINT UNSIGNED NOT NULL,
    flags            BIGINT UNSIGNED NOT NULL DEFAULT 0,
    user_id          BIGINT UNSIGNED NOT NULL,
    mac              VARCHAR(255) NOT NULL,
    created_at       DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY recovery_codes_recovery_code_xid (recovery_code_xid),
    UNIQUE KEY recovery_codes_mac (mac),
    KEY              recovery_codes_user_id (user_id),
    CONSTRAINT recovery_codes_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE recovery_requests
(
    id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    recovery_request_xid BIGINT UNSIGNED NOT NULL,
    flags                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    user_id              BIGINT UNSIGNED NOT NULL,
    cancel_hash          VARBINARY(32) NOT NULL,
    grant_hash           VARBINARY(32) NOT NULL DEFAULT 0x00,
    grant_expires_at     DATETIME(6) NULL,
    ready_at             DATETIME(6) NOT NULL,
    created_at           DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY recovery_requests_recovery_request_xid (recovery_request_xid),
    KEY                  recovery_requests_cancel_hash (cancel_hash),
    KEY                  recovery_requests_grant_hash (grant_hash),
    KEY                  recovery_requests_user_id (user_id, id),
    CONSTRAINT recovery_requests_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE sessions
(
    id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_xid          BIGINT UNSIGNED NOT NULL,
    flags                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    user_id              BIGINT UNSIGNED NULL,
    auth_time            DATETIME(6) NULL,
    risk_score           TINYINT UNSIGNED NOT NULL DEFAULT 0,
    failures             SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    device_id_hash       VARBINARY(32) NOT NULL DEFAULT 0x00,
    device_key           VARBINARY(32) NOT NULL DEFAULT 0x00,
    key_id               VARBINARY(32) NOT NULL DEFAULT 0x00,
    ip                   VARBINARY(16) NULL,
    country              CHAR(2) NOT NULL DEFAULT '',
    latitude DOUBLE NOT NULL DEFAULT 0,
    longitude DOUBLE NOT NULL DEFAULT 0,
    verify_hash          VARBINARY(32) NOT NULL DEFAULT 0x00,
    verify_expires_at    DATETIME(6) NULL,
    challenge            BLOB    NOT NULL,
    challenge_expires_at DATETIME(6) NULL,
    created_at           DATETIME(6) NOT NULL,
    last_seen_at         DATETIME(6) NOT NULL,
    expires_at           DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY sessions_session_xid (session_xid),
    KEY                  sessions_user_created (user_id, created_at),
    KEY                  sessions_ip_created (ip, created_at),
    KEY                  sessions_expires (expires_at),
    CONSTRAINT sessions_user FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE http_requests
(
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    resource_code SMALLINT UNSIGNED NOT NULL,
    method        VARCHAR(8) NOT NULL,
    status_code   SMALLINT UNSIGNED NOT NULL,
    error_code    SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    duration_ms   INT UNSIGNED NOT NULL,
    session_xid   BIGINT UNSIGNED NOT NULL DEFAULT 0,
    user_xid      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    ip            VARBINARY(16) NULL,
    path          VARCHAR(255) NOT NULL,
    request_id    VARCHAR(64) NOT NULL,
    host          VARCHAR(255) NOT NULL,
    user_agent    VARCHAR(255) NOT NULL,
    build_version VARCHAR(64) NOT NULL,
    event         VARCHAR(64) NOT NULL DEFAULT '',
    event_attrs   VARCHAR(255) NOT NULL DEFAULT '',
    error_text    VARCHAR(255) NOT NULL DEFAULT '',
    created_at    DATETIME(6) NOT NULL,
    PRIMARY KEY (id),
    KEY http_requests_created (created_at),
    KEY http_requests_event (event, created_at),
    KEY http_requests_user (user_xid, created_at)
);

-- +goose Down
DROP TABLE http_requests;
DROP TABLE sessions;
DROP TABLE recovery_codes;
DROP TABLE passkeys;
DROP TABLE users;
