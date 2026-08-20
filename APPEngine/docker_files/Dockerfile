FROM ubuntu:jammy

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /python-docker
ENV CELERY_BROKER_URL redis://redis:6379/0
ENV CELERY_RESULT_BACKEND redis://redis:6379/0
ENV C_FORCE_ROOT true

#ARG PROXY_USER
#ARG PROXY_USER_PWD
#ARG HTTP_PROXY_URL
#ARG HTTPS_PROXY_URL

#RUN echo 'Acquire::http::Proxy "http://${PROXY_USER}:${PROXY_USER_PWD}@${HTTP_PROXY_URL}";' > /etc/apt/apt.conf.d/10proxy \
#        && echo 'Acquire::https::Proxy "http://${PROXY_USER}:${PROXY_USER_PWD}@${HTTPS_PROXY_URL}";' >> /etc/apt/apt.conf.d/10proxy

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
    python3-dev \
    build-essential \
    nano \
    git \
    curl \
    wget \
    p7zip-full && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY docker_files/requirements.txt requirements.txt
RUN pip3 install --upgrade pip && \
    pip3 install -U setuptools pip && \
    pip3 install --upgrade py7zr && \
    pip3 install -r requirements.txt --ignore-installed

COPY docker_files/yarp-1.0.33.tar.gz yarp-1.0.33.tar.gz
RUN pip3 install ./yarp-1.0.33.tar.gz

COPY docker_files/install_analyzemft.sh install_analyzemft.sh
RUN ./install_analyzemft.sh

# --- Configure and Set Entrypoint ---
COPY docker_files/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]

COPY . .
RUN useradd -m -u 1000 appuser && chown -R appuser /python-docker
USER appuser
