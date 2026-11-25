#!/bin/bash
umask 0002

id

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh
. /reach_database.sh
. /reach_broker.sh

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

if [ "${ORASEC_CELERY_WORKER_POOL_TYPE}" = "prefork" ]; then
  EXTRA_PARAMS=("--autoscale=${ORASEC_CELERY_WORKER_AUTOSCALE_MAX},${ORASEC_CELERY_WORKER_AUTOSCALE_MIN}"
    "--prefetch-multiplier=${ORASEC_CELERY_WORKER_PREFETCH_MULTIPLIER}")
else
  EXTRA_PARAMS=()
fi

# do the check with Django stack
python3 manage.py check

exec celery --app=orasec \
    worker \
  --loglevel="${ORASEC_CELERY_LOG_LEVEL}" \
  --pool="${ORASEC_CELERY_WORKER_POOL_TYPE}" \
  --concurrency="${ORASEC_CELERY_WORKER_CONCURRENCY:-1}" \
  "${EXTRA_PARAMS[@]}"