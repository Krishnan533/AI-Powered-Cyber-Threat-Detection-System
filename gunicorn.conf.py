import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
# Default to 2 workers to prevent memory exhaustion (OOM) on containerized platforms like Render
default_workers = min(multiprocessing.cpu_count() * 2 + 1, 4) if os.environ.get('WEB_CONCURRENCY') is None else int(os.environ.get('WEB_CONCURRENCY'))
workers = int(os.environ.get('WEB_CONCURRENCY', 2))
worker_class = "sync"
timeout = 120
keepalive = 5

loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
accesslog = "-"
errorlog = "-"

# Do not preload app to ensure each worker initializes DB connections and background threads safely after fork
preload_app = False

