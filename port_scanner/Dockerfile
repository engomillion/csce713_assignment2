FROM python:3.9-slim

# Install dependencies for your scanner
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    net-tools \
    iproute2 \
    iputils-ping \
    gcc \
    python3-dev \
    vim \
    procps \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir \
    ipaddress

# Copy your scanner
COPY port_scanner.py /app/
WORKDIR /app

RUN chmod +x port_scanner.py

# Keep container running (scanner runs manually)
CMD ["tail", "-f", "/dev/null"]
