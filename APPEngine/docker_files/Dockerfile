FROM log2timeline/plaso:20240308

USER root
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_BREAK_SYSTEM_PACKAGES=1
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

RUN if [ -f /etc/apt/sources.list ]; then \
        sed -i 's|http://archive.ubuntu.com/ubuntu/|http://fr.archive.ubuntu.com/ubuntu/|g' /etc/apt/sources.list && \
        sed -i 's|http://security.ubuntu.com/ubuntu/|http://fr.archive.ubuntu.com/ubuntu/|g' /etc/apt/sources.list; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    nano \
    git \
    curl \
    wget \
    p7zip-full && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY docker_files/requirements.txt requirements.txt
RUN pip3 install --ignore-installed setuptools py7zr && \
    pip3 install --ignore-installed -r requirements.txt

COPY docker_files/yarp-1.0.33.tar.gz yarp-1.0.33.tar.gz
RUN pip3 install ./yarp-1.0.33.tar.gz

COPY docker_files/install_analyzemft.sh install_analyzemft.sh
RUN ./install_analyzemft.sh

# Installation native de DFIR-OGRE depuis Git via uv (gère les dépendances imbriquées complexes)
RUN pip3 install uv && \
    git clone --branch 2.0.0-beta2 https://github.com/ANSSI-FR/dfir-ogre.git /opt/dfir-ogre && \
    cd /opt/dfir-ogre && \
    uv pip install --system --break-system-packages . && \
    git clone https://github.com/ANSSI-FR/dfir-ogre-plugin-windows.git /opt/dfir-ogre-plugin-windows && \
    sed -i 's|plugin_folder: dfir-ogre-plugin-windows/configuration/|plugin_folder: /opt/dfir-ogre-plugin-windows/configuration/|g' /opt/dfir-ogre/configuration/ogre.yaml

# --- Configure and Set Entrypoint ---
COPY docker_files/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]

COPY . .

RUN useradd -m -o -u 1000 appuser && chown -R appuser /python-docker
USER appuser
