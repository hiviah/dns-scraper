-- __SCHEMAPLACEHOLDER__ will be replaced by sed for actual schema name
SET search_path = __SCHEMAPLACEHOLDER__;
CREATE INDEX rrsig_rr_fqdn_id_type_idx ON rrsig_rr (fqdn_id, rr_type);
CREATE INDEX aa_rr_fqdn_id_idx ON aa_rr (fqdn_id);
CREATE INDEX dnskey_rr_fqdn_id_algo_idx ON dnskey_rr (fqdn_id, algo);
CREATE INDEX nsec_rr_fqdn_id_idx ON nsec_rr (fqdn_id, rr_type);
CREATE INDEX nsec3_rr_fqdn_id_idx ON nsec3_rr (fqdn_id, rr_type);
CREATE INDEX ns_rr_fqdn_id_idx ON ns_rr (fqdn_id);
CREATE INDEX ds_rr_fqdn_id_idx ON ds_rr (fqdn_id);
CREATE INDEX soa_rr_fqdn_id_idx ON soa_rr (fqdn_id);
CREATE INDEX sshfp_rr_fqdn_id_idx ON sshfp_rr (fqdn_id);
CREATE INDEX txt_rr_fqdn_id_idx ON txt_rr (fqdn_id);
CREATE INDEX spf_rr_fqdn_id_idx ON spf_rr (fqdn_id);
CREATE INDEX nsec3param_rr_fqdn_id_idx ON nsec3param_rr (fqdn_id);
CREATE INDEX mx_rr_fqdn_id_idx ON mx_rr (fqdn_id);
