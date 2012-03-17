DROP TABLE IF EXISTS a_rr;
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
    signature VARCHAR NOT NULL
);

-- Table for As
CREATE TABLE a_rr (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    ttl INTEGER NOT NULL,
    rr INET NOT NULL,
    rrsig_id INTEGER REFERENCES rrsig_rr(id)
);

