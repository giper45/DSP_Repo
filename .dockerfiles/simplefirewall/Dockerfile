FROM alpine:latest


# Install dependencies
RUN apk --update add \
    iptables \
    netcat-openbsd
    

RUN apk add --update --no-cache python2 && ln -sf python3 /usr/bin/python
RUN python2 -m ensurepip
RUN pip2 install --no-cache --upgrade pip setuptools

RUN mkdir /firewall
COPY ./setup.sh /firewall/setup.sh


RUN chmod +x /firewall/setup.sh
ENTRYPOINT ["/firewall/setup.sh"]

CMD ["bin/sh"]