#!/bin/bash
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

umask 0002

# do the check with Django stack
python3 manage.py check

ORASEC_UWSGI_LOGFORMAT_DEFAULT='[pid: %(pid)|app: -|req: -/-] %(addr) (%(dd_user)) {%(vars) vars in %(pktsize) bytes} [%(ctime)] %(method) %(uri) => generated %(rsize) bytes in %(msecs) msecs (%(proto) %(status)) %(headers) headers in %(hsize) bytes (%(switches) switches on core %(core))'

ORASEC_UWSGI_EXTRA_ARGS="${ORASEC_UWSGI_EXTRA_ARGS:-}"
if [ -n "${ORASEC_UWSGI_MAX_FD}" ]; then
    ORASEC_UWSGI_EXTRA_ARGS="${ORASEC_UWSGI_EXTRA_ARGS} --max-fd ${ORASEC_UWSGI_MAX_FD}"
fi

exec uwsgi \
  "--${ORASEC_UWSGI_MODE}" "${ORASEC_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --enable-threads \
  --processes "${ORASEC_UWSGI_NUM_OF_PROCESSES:-4}" \
  --threads "${ORASEC_UWSGI_NUM_OF_THREADS:-4}" \
  --wsgi orasec.wsgi:application \
  --buffer-size="${ORASEC_UWSGI_BUFFER_SIZE:-8192}" \
  --http 0.0.0.0:8081 --http-to "${ORASEC_UWSGI_ENDPOINT}" \
  --logformat "${ORASEC_UWSGI_LOGFORMAT:-$ORASEC_UWSGI_LOGFORMAT_DEFAULT}" \
  $ORASEC_UWSGI_EXTRA_ARGS
  # HTTP endpoint is enabled for Kubernetes liveness checks. It should not be exposed as a service.
