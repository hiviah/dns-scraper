#!/bin/bash
PREFIX=$1
cat create_tables_template.sql | sed 's/.*TABLE.*aa\_rr/'$PREFIX'\.aa\_rr/g' \
| sed 's/.*TABLE.*dnskey\_rr/'$PREFIX'\.dnskey\_rr/g' \
| sed 's/.*TABLE.*ns\_rr/'$PREFIX'\.ns\_rr/g' \
| sed 's/.*TABLE.*ds\_rr/'$PREFIX'\.ds\_rr/g' \
| sed 's/.*TABLE.*soa\_rr/'$PREFIX'\.soa\_rr/g' \
| sed 's/.*TABLE.*sshfp\_rr/'$PREFIX'\.sshfp\_rr/g' \
| sed 's/.*TABLE.*txt\_rr/'$PREFIX'\.txt\_rr/g' \
| sed 's/.*TABLE.*spf\_rr/'$PREFIX'\.spf\_rr/g' \
| sed 's/.*TABLE.*nsec3param\_rr/'$PREFIX'\.nsec3param\_rr/g' \
| sed 's/.*TABLE.*mx\_rr/'$PREFIX'\.mx\_rr/g' \
| sed 's/.*TABLE.*nsec\_rr/'$PREFIX'\.nsec\_rr/g' \
| sed 's/.*TABLE.*nsec3\_rr/'$PREFIX'\.nsec3\_rr/g' \
| sed 's/.*TABLE.*rrsig\_rr/'$PREFIX'\.rrsig\_rr/g' \
| sed 's/OURSCHEMA/'$PREFIX'/' > $2
