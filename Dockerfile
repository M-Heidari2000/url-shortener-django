FROM python:3.10.6-slim-buster

ENV PYTHONUNBUFFERED 1

RUN mkdir /code
WORKDIR /code

COPY . /code/

RUN pip install -r requirements.txt
