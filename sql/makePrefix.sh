#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: makePrefix.sh schema_name"
    echo "Prints out SQL for creation of schema and tables"
    exit 1
fi

sed s/__SCHEMAPLACEHOLDER__/"$1"/g "${0%%/*}/create_tables_template.sql"

