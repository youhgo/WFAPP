# syntax=docker/dockerfile:1
FROM ubuntu:jammy

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /python-docker
ENV CELERY_BROKER_URL redis://redis:6379/0
ENV CELERY_RESULT_BACKEND redis://redis:6379/0
ENV C_FORCE_ROOT true

# Combine all apt-get commands into a single RUN instruction for efficiency.
# This reduces the number of image layers and prevents "404 Not Found" errors
# by ensuring the package list is up-to-date before installation.
# The `add-apt-repository` commands are also included here.
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
    curl && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python packages from requirements.txt
COPY WAPP_MODULE/docker_files/requirements.txt requirements.txt
RUN pip3 install --upgrade pip && \
    pip3 install -U setuptools pip && \
    pip3 install -r requirements.txt --ignore-installed

# Install yarp package from local tarball
COPY WAPP_MODULE/docker_files/yarp-1.0.33.tar.gz yarp-1.0.33.tar.gz
RUN pip3 install ./yarp-1.0.33.tar.gz

# Run the install script for analyzeMFT
COPY WAPP_MODULE/docker_files/install_analyzemft.sh install_analyzemft.sh
RUN ./install_analyzemft.sh

# Copy the rest of the application code
COPY . .

# Note: The commented out line below is unnecessary as the cleanup is already
# performed in the combined RUN command above.
# #RUN apt-get install -y --no-install-recommends libmagic1 && rm -rf /var/lib/apt/lists/*
