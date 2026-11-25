#!/bin/bash
umask 0002

id

set -e  # needed to handle "exit" correctly

. /secret-file-loader.sh
. /reach_database.sh
. /reach_broker.sh

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

# hot reload using watmedo as we don't want to install celery[dev] and have that end up in our production images
watchmedo auto-restart --directory=./ --pattern="*.py;*.tpl" --recursive -- \
  celery --app=orasec worker --loglevel="${ORASEC_CELERY_LOG_LEVEL}" --pool="${ORASEC_CELERY_WORKER_POOL_TYPE}" --concurrency="${ORASEC_CELERY_WORKER_CONCURRENCY:-1}" "${EXTRA_PARAMS[@]}"
