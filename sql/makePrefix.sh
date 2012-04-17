#!/bin/bash
PREFIX=$1
cat create_tables_template.sql | sed 's/aa\_rr/'$PREFIX'\.aa\_rr/g' \
| sed 's/dnskey\_rr/'$PREFIX'\.dnskey\_rr/g' \
| sed 's/ns\_rr/'$PREFIX'\.ns\_rr/g' \
| sed 's/ds\_rr/'$PREFIX'\.ds\_rr/g' \
| sed 's/soa\_rr/'$PREFIX'\.soa\_rr/g' \
| sed 's/sshfp\_rr/'$PREFIX'\.sshfp\_rr/g' \
| sed 's/txt\_rr/'$PREFIX'\.txt\_rr/g' \
| sed 's/spf\_rr/'$PREFIX'\.spf\_rr/g' \
| sed 's/nsec3param\_rr/'$PREFIX'\.nsec3param\_rr/g' \
| sed 's/mx\_rr/'$PREFIX'\.mx\_rr/g' \
| sed 's/nsec\_rr/'$PREFIX'\.nsec\_rr/g' \
| sed 's/nsec3\_rr/'$PREFIX'\.nsec3\_rr/g' \
| sed 's/rrsig\_rr/'$PREFIX'\.rrsig\_rr/g' \
| sed 's/OURSCHEMA/'$PREFIX'/' > $2
