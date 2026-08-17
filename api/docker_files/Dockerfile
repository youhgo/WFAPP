FROM python:3.12-slim-bookworm

WORKDIR /python-docker

#ARG PROXY_USER
#ARG PROXY_USER_PWD
#ARG HTTP_PROXY_URL
#ARG HTTPS_PROXY_URL

#RUN echo 'Acquire::http::Proxy "http://${PROXY_USER}:${PROXY_USER_PWD}@${HTTP_PROXY_URL}";' > /etc/apt/apt.conf.d/10proxy \
#        && echo 'Acquire::https::Proxy "http://${PROXY_USER}:${PROXY_USER_PWD}@${HTTPS}";' >> /etc/apt/apt.conf.d/10proxy

RUN apt-get update && apt-get install -y --no-install-recommends \
    nano \
    python3-dev \
    wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /python-docker/static/vendor/fonts
RUN wget -O /python-docker/static/vendor/tailwindcss.js https://cdn.tailwindcss.com
RUN wget -O /python-docker/static/vendor/inter.css "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" --header="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/5.37.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"

RUN cd /python-docker/static/vendor && \
    grep -o 'url(https://[^)]*)' inter.css | \
    sed -e 's/url(//' -e 's/)//' | \
    wget --header="User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/5.37.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36" -i - -P fonts/ && \
    sed -i 's|https://fonts.gstatic.com/s/inter/v[0-9]*/|../fonts/|g' inter.css

COPY docker_files/requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .
RUN useradd -m -u 1000 appuser && chown -R appuser /python-docker
USER appuser
CMD [ "python3",  "wapp_server.py"]

