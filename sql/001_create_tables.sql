DROP TABLE IF EXISTS aa_rr;
DROP TABLE IF EXISTS dnskey_rr;
DROP TABLE IF EXISTS rrsig_rr;

-- Table for RRSIGs
CREATE TABLE rrsig_rr (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    rr_type INTEGER NOT NULL,
    algo INTEGER NOT NULL,
    labels INTEGER NOT NULL,
    orig_ttl INTEGER NOT NULL,
    sig_expiration TIMESTAMP NOT NULL,
    sig_inception TIMESTAMP NOT NULL,
    keytag INTEGER NOT NULL,
    signer VARCHAR(255) NOT NULL,
    signature BYTEA NOT NULL
);

CREATE INDEX rrsig_rr_domain_idx ON rrsig_rr (domain);

-- Table for A and AAAA records
CREATE TABLE aa_rr (
    id SERIAL PRIMARY KEY,
    secure BOOLEAN,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    addr INET NOT NULL,
    rrsig_id INTEGER REFERENCES rrsig_rr(id)
);

CREATE INDEX aa_rr_domain_idx ON aa_rr (domain);

-- Table for DNSKEY
CREATE TABLE dnskey_rr (
    id SERIAL PRIMARY KEY,
    secure BOOLEAN,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    flags SMALLINT NOT NULL,
    protocol SMALLINT NOT NULL,
    algo SMALLINT NOT NULL,
    pubkey BYTEA NOT NULL,
    rrsig_id INTEGER REFERENCES rrsig_rr(id)
);

CREATE INDEX dnskey_rr_domain_idx ON dnskey_rr (domain);

