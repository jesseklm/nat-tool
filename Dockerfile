FROM python:3.13-alpine

WORKDIR /usr/src/app

COPY . .

CMD [ "python", "./stun_server_test.py" ]
