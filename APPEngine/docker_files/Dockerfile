# syntax=docker/dockerfile:1
FROM ubuntu:jammy

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /python-docker
ENV CELERY_BROKER_URL redis://redis:6379/0
ENV CELERY_RESULT_BACKEND redis://redis:6379/0
ENV C_FORCE_ROOT true

# Set Filebeat version as an argument for easy updates
ARG FILEBEAT_VERSION=8.11.1

# Combine all apt-get commands into a single RUN instruction for efficiency.
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository universe && \
    add-apt-repository ppa:gift/stable && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    libscca-python3 \
    plaso-tools \
    python3.10 \
    python3-pip \
    nano \
    git \
    curl \
    # Add wget for downloading Filebeat
    wget && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# --- Add Filebeat Installation ---
RUN wget --no-check-certificate https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-${FILEBEAT_VERSION}-amd64.deb && \
    dpkg -i filebeat-${FILEBEAT_VERSION}-amd64.deb && \
    rm filebeat-${FILEBEAT_VERSION}-amd64.deb

# Copy the Filebeat configuration file into the correct location
COPY docker_files/filebeat.yml /etc/filebeat/filebeat.yml
# ---------------------------------

# Install Python packages from requirements.txt
COPY docker_files/requirements.txt requirements.txt
RUN pip3 install --upgrade pip && \
    pip3 install -U setuptools pip && \
    pip3 install -r requirements.txt --ignore-installed

# Install yarp package from local tarball
COPY docker_files/yarp-1.0.33.tar.gz yarp-1.0.33.tar.gz
RUN pip3 install ./yarp-1.0.33.tar.gz

# Run the install script for analyzeMFT
COPY docker_files/install_analyzemft.sh install_analyzemft.sh
RUN ./install_analyzemft.sh

# --- Configure and Set Entrypoint ---
# Copy the new entrypoint script
COPY docker_files/entrypoint.sh /usr/local/bin/entrypoint.sh

# Make the script executable
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set the entrypoint for the container
ENTRYPOINT ["entrypoint.sh"]
# ------------------------------------

# Copy the rest of the application code
COPY . .

# The CMD will be inherited from the 'command' in your docker-compose.yml
