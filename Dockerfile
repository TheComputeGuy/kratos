FROM python:3

WORKDIR /usr/src/app

COPY . .

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && \
    apt-get install -y sudo libfuzzy-dev libmagic-dev php7.4 php7.4-dev php7.4-xml php7.4-xmlwriter php7.4-mbstring php7.4-curl && \
    pip install --no-cache-dir -r requirements.txt && \
    cd ./ast_utils && \
    ./ast_vendor_setup.sh && \
    cd /usr/src/app

CMD [ "python", "./framework.py" ]
