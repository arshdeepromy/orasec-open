#!/bin/bash

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh
. /reach_database.sh
. /reach_broker.sh

wait_for_database_to_be_reachable
wait_for_broker_to_be_reachable
echo

cd /app || exit

# Full list of uwsgi options: https://uwsgi-docs.readthedocs.io/en/latest/Options.html
# --lazy-apps required for debugging --> https://uwsgi-docs.readthedocs.io/en/latest/articles/TheArtOfGracefulReloading.html?highlight=lazy-apps#preforking-vs-lazy-apps-vs-lazy

ORASEC_UWSGI_LOGFORMAT_DEFAULT='[pid: %(pid)|app: -|req: -/-] %(addr) (%(dd_user)) {%(vars) vars in %(pktsize) bytes} [%(ctime)] %(method) %(uri) => generated %(rsize) bytes in %(msecs) msecs (%(proto) %(status)) %(headers) headers in %(hsize) bytes (%(switches) switches on core %(core))'

if [ "${ORASEC_DEBUG}" = "True" ]; then
  echo "Debug mode enabled, reducing # of processes and threads to 1"
  ORASEC_UWSGI_NUM_OF_PROCESSES=1
  ORASEC_UWSGI_NUM_OF_THREADS=1
fi

# hot reload also on html/template changes
watchmedo shell-command \
  --patterns="*.html;*.tpl" \
  --recursive \
  --command='touch /app/orasec/settings/settings.py' \
  /app/orasec &


exec uwsgi \
  "--${ORASEC_UWSGI_MODE}" "${ORASEC_UWSGI_ENDPOINT}" \
  --protocol uwsgi \
  --wsgi orasec.wsgi:application \
  --enable-threads \
  --processes "${ORASEC_UWSGI_NUM_OF_PROCESSES:-4}" \
  --threads "${ORASEC_UWSGI_NUM_OF_THREADS:-4}" \
  --reload-mercy 1 \
  --worker-reload-mercy 1 \
  --py-autoreload 1 \
  --buffer-size="${ORASEC_UWSGI_BUFFER_SIZE:-8192}" \
  --lazy-apps \
  --touch-reload="/app/orasec/settings/settings.py" \
  --logformat "${ORASEC_UWSGI_LOGFORMAT:-$ORASEC_UWSGI_LOGFORMAT_DEFAULT}"
