FROM golang:1.17.3-alpine3.15 AS util

RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_passwd

FROM scratch

ENV PATH=/bin

COPY jwtpxy /bin/
COPY --from=util /etc_passwd /etc/passwd
COPY --from=util /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

WORKDIR /

USER nobody
ENTRYPOINT ["/bin/jwtpxy"]