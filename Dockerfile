FROM python:3.13-alpine

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

CMD [ "python", "./stun_server_test.py" ]
