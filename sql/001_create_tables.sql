DROP TABLE IF EXISTS aa_rr;
DROP TABLE IF EXISTS dnskey_rr;
DROP TABLE IF EXISTS rrsig_rr;
DROP TYPE  IF EXISTS validation_result;

CREATE TYPE validation_result AS ENUM ('insecure', 'secure', 'bogus');

-- Table for RRSIGs
CREATE TABLE rrsig_rr (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    rr_type INTEGER NOT NULL,
    algo SMALLINT NOT NULL,
    labels SMALLINT NOT NULL,
    orig_ttl INTEGER NOT NULL,
    sig_expiration TIMESTAMP NOT NULL,
    sig_inception TIMESTAMP NOT NULL,
    keytag INTEGER NOT NULL,
    signer VARCHAR(255) NOT NULL,
    signature BYTEA NOT NULL
);

CREATE INDEX rrsig_rr_domain_type_idx ON rrsig_rr (domain, rr_type);

-- Table for A and AAAA records
CREATE TABLE aa_rr (
    id SERIAL PRIMARY KEY,
    secure validation_result,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    addr INET NOT NULL
);

CREATE INDEX aa_rr_domain_idx ON aa_rr (domain);

-- Table for DNSKEY
CREATE TABLE dnskey_rr (
    id SERIAL PRIMARY KEY,
    secure validation_result,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    flags INTEGER NOT NULL,
    protocol SMALLINT NOT NULL,
    algo SMALLINT NOT NULL,
    rsa_exp INTEGER, -- bigger exponents will have -1 here and pubkey will be unparsed in other_key field
    rsa_mod BYTEA, -- RSA exponent without leading zeros if exponent fits in rsa_exp
    other_key BYTEA -- all other non-RSA keys unparsed (including RSA keys with too large exponent)
);

CREATE INDEX dnskey_rr_domain_algo_idx ON dnskey_rr (domain, algo);

