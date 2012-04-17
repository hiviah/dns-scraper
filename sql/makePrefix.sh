#!/bin/bash
PREFIX=$1
cat create_tables_template.sql | sed 's/TABLE\ aa\_rr/TABLE\ '$PREFIX'\.aa\_rr/g' \
| sed 's/TABLE\ dnskey\_rr/TABLE\ '$PREFIX'\.dnskey\_rr/g' \
| sed 's/TABLE\ ns\_rr/TABLE\ '$PREFIX'\.ns\_rr/g' \
| sed 's/TABLE\ ds\_rr/TABLE\ '$PREFIX'\.ds\_rr/g' \
| sed 's/TABLE\ soa\_rr/TABLE\ '$PREFIX'\.soa\_rr/g' \
| sed 's/TABLE\ sshfp\_rr/TABLE\ '$PREFIX'\.sshfp\_rr/g' \
| sed 's/TABLE\ txt\_rr/TABLE\ '$PREFIX'\.txt\_rr/g' \
| sed 's/TABLE\ spf\_rr/TABLE\ '$PREFIX'\.spf\_rr/g' \
| sed 's/TABLE\ nsec3param\_rr/TABLE\ '$PREFIX'\.nsec3param\_rr/g' \
| sed 's/TABLE\ mx\_rr/TABLE\ '$PREFIX'\.mx\_rr/g' \
| sed 's/TABLE\ nsec\_rr/TABLE\ '$PREFIX'\.nsec\_rr/g' \
| sed 's/TABLE\ nsec3\_rr/TABLE\ '$PREFIX'\.nsec3\_rr/g' \
| sed 's/TABLE\ rrsig\_rr/TABLE\ '$PREFIX'\.rrsig\_rr/g' \
| sed 's/ON\ aa\_rr/On\ '$PREFIX'\.aa\_rr/g' \
| sed 's/ON\ dnskey\_rr/ON\ '$PREFIX'\.dnskey\_rr/g' \
| sed 's/ON\ ns\_rr/ON\ '$PREFIX'\.ns\_rr/g' \
| sed 's/ON\ ds\_rr/ON\ '$PREFIX'\.ds\_rr/g' \
| sed 's/ON\ soa\_rr/ON\ '$PREFIX'\.soa\_rr/g' \
| sed 's/ON\ sshfp\_rr/ON\ '$PREFIX'\.sshfp\_rr/g' \
| sed 's/ON\ txt\_rr/ON\ '$PREFIX'\.txt\_rr/g' \
| sed 's/ON\ spf\_rr/ON\ '$PREFIX'\.spf\_rr/g' \
| sed 's/ON\ nsec3param\_rr/ON\ '$PREFIX'\.nsec3param\_rr/g' \
| sed 's/ON\ mx\_rr/ON\ '$PREFIX'\.mx\_rr/g' \
| sed 's/ON\ nsec\_rr/ON\ '$PREFIX'\.nsec\_rr/g' \
| sed 's/ON\ nsec3\_rr/ON\ '$PREFIX'\.nsec3\_rr/g' \
| sed 's/ON\ rrsig\_rr/ON\ '$PREFIX'\.rrsig\_rr/g' \
| sed 's/OURSCHEMA/'$PREFIX'/' > $2
