FROM python:3.12-slim

# Install system dependencies needed for packet capturing (libpcap/tcpdump) and compiling C-extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tcpdump \
    libpcap-dev \
    libpq-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Expose server port
EXPOSE 5000

# Set environment defaults
ENV FLASK_APP=backend/app.py
ENV FLASK_ENV=production

# Start Gunicorn WSGI production server
CMD ["gunicorn", "-c", "gunicorn.conf.py", "backend.app:create_app()"]
