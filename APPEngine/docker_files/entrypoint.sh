#!/bin/sh


#echo "Starting Filebeat service in the background..."
#filebeat -e &

# Start the Celery worker as the main process.
# This command is now hardcoded here instead of in docker-compose.yml.
echo "Starting Celery worker..."
exec celery -A tasks worker -l info -E -Q parse