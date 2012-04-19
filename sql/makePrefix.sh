#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: makePrefix.sh schema_name"
    echo "Stores SQL statemets for creation of schema.tables and schema.indices in two .sql files."
    exit 1
fi

sed s/__SCHEMAPLACEHOLDER__/"$1"/g "${0%%/*}/create_tables_template.sql" > $1_tables.sql
sed s/__SCHEMAPLACEHOLDER__/"$1"/g "${0%%/*}/create_indices_template.sql" > $1_indices.sql

