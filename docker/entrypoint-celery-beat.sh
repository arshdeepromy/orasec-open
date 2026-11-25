#!/bin/bash

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh
. /reach_database.sh
. /reach_broker.sh

umask 0002

id

# Allow for bind-mount multiple settings.py overrides
FILES=$(ls /app/docker/extra_settings/* 2>/dev/null || true)
NUM_FILES=$(echo "$FILES" | wc -w)
if [ "$NUM_FILES" -gt 0 ]; then
    COMMA_LIST=$(echo "$FILES" | tr -s '[:blank:]' ', ')
    echo "============================================================"
    echo "     Overriding OraSec's local_settings.py with multiple"
    echo "     Files: $COMMA_LIST"
    echo "============================================================"
    cp /app/docker/extra_settings/* /app/orasec/settings/
    rm -f /app/orasec/settings/README.md
fi

wait_for_database_to_be_reachable
wait_for_broker_to_be_reachable
echo

# do the check with Django stack
python3 manage.py check

exec celery --app=orasec \
    beat \
  --pidfile=/var/run/orasec/celery-beat.pid \
  --schedule=/var/run/orasec/celerybeat-schedule
