#!/bin/sh

# Start the Celery worker as the main process.
echo "Starting Celery worker..."
exec celery -A tasks worker -l info -E -Q parse