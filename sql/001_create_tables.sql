DROP TABLE IF EXISTS aa_rr;
DROP TABLE IF EXISTS dnskey_rr;
DROP TABLE IF EXISTS ns_rr;
DROP TABLE IF EXISTS ds_rr;

DROP TABLE IF EXISTS nsec_rr;
DROP TABLE IF EXISTS nsec3_rr;
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
    sig_expiration TIMESTAMP WITH TIME ZONE NOT NULL,
    sig_inception TIMESTAMP WITH TIME ZONE NOT NULL,
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
    rsa_exp BIGINT, -- bigger exponents will have -1 here and pubkey will be unparsed in other_key field
    rsa_mod BYTEA, -- RSA exponent without leading zeros if exponent fits in rsa_exp
    other_key BYTEA -- all other non-RSA keys unparsed (including RSA keys with too large exponent)
);

CREATE INDEX dnskey_rr_domain_algo_idx ON dnskey_rr (domain, algo);

-- Table for NSEC records
CREATE TABLE nsec_rr (
    id SERIAL PRIMARY KEY,
    secure validation_result,
    domain VARCHAR(255) NOT NULL,
    rr_type INTEGER NOT NULL, -- RR type that was used in question
    owner VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    rcode SMALLINT NOT NULL,
    next_domain VARCHAR(255) NOT NULL,
    type_bitmap INTEGER[] NOT NULL
);

CREATE INDEX nsec_rr_domain_idx ON nsec_rr (domain, rr_type);

-- Table for NSEC3 records
CREATE TABLE nsec3_rr (
    id SERIAL PRIMARY KEY,
    secure validation_result,
    domain VARCHAR(255) NOT NULL,
    rr_type INTEGER NOT NULL, -- RR type that was used in question
    owner VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    rcode SMALLINT NOT NULL,
    hash_algo SMALLINT NOT NULL,
    flags SMALLINT NOT NULL,
    iterations INTEGER NOT NULL,
    salt BYTEA NOT NULL,
    next_owner VARCHAR(255) NOT NULL,
    type_bitmap INTEGER[] NOT NULL
);

CREATE INDEX nsec3_rr_domain_idx ON nsec3_rr (domain, rr_type);

-- Table for NS records
CREATE TABLE ns_rr (
    id SERIAL PRIMARY KEY,
    secure validation_result,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    nameserver VARCHAR(255) NOT NULL
);

CREATE INDEX ns_rr_domain_idx ON ns_rr (domain);

-- Table for DS records
CREATE TABLE ds_rr (
    id SERIAL PRIMARY KEY,
    secure validation_result,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    keytag INTEGER NOT NULL,
    algo SMALLINT NOT NULL,
    digest_type SMALLINT NOT NULL,
    digest BYTEA NOT NULL
);

CREATE INDEX ds_rr_domain_idx ON ds_rr (domain);



