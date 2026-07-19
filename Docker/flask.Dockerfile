FROM python:3.12-slim

# Install system dependencies needed for packet capturing (libpcap) and compiling requirements
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    tcpdump \
    libpcap-dev \
    libmariadb-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code files
COPY . .

# Expose server port
EXPOSE 5000

# Set dynamic execution defaults
ENV FLASK_APP=backend/app.py
ENV FLASK_ENV=production

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "backend.app:create_app()"]
