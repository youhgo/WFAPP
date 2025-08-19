#syntax=docker/dockerfile:1
#FROM python:3.10-slim-buster
FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /python-docker
ENV CELERY_BROKER_URL redis://redis:6379/0
ENV CELERY_RESULT_BACKEND redis://redis:6379/0
ENV C_FORCE_ROOT true

RUN apt-get update
RUN apt-get install -y software-properties-common
RUN add-apt-repository universe
RUN add-apt-repository ppa:gift/stable
RUN apt-get update
RUN apt-get install -y libscca-python3
RUN apt-get install -y \
    plaso-tools \
    python3.10 \
    python3-pip \
    nano \
    git


RUN apt-get upgrade -y
RUN pip3 install --upgrade pip

COPY DOPP_MODULE/docker_files/requirements.txt requirements.txt
RUN pip3 install -U setuptools pip
RUN pip3 install -r requirements.txt --ignore-installed

COPY DOPP_MODULE/docker_files/yarp-1.0.33.tar.gz yarp-1.0.33.tar.gz
RUN pip3 install ./yarp-1.0.33.tar.gz

COPY . .
#RUN apt-get install -y --no-install-recommends libmagic1 && rm -rf /var/lib/apt/lists/*

