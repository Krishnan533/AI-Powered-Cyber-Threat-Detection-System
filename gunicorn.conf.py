import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"
workers = int(os.environ.get('WEB_CONCURRENCY', multiprocessing.cpu_count() * 2 + 1))
worker_class = "sync"
timeout = 120
keepalive = 5

loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')
accesslog = "-"
errorlog = "-"

preload_app = True
