FROM python:3.9-bullseye

# Install system dependencies
RUN apt-get update && apt-get install -y \
    netcat-openbsd \
    socat \
    iptables \
    curl \
    gnupg \
    && apt-get install -y ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 600 -r requirements.txt
# Copy application code
COPY . /app
WORKDIR /app

# Create log directory
RUN mkdir -p /var/log/rl-agent

# Make entrypoint executable
RUN chmod +x ./entrypoint.sh

# Set entrypoint
ENTRYPOINT ["./entrypoint.sh"]
