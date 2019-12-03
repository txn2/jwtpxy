FROM alpine3.10 AS util

RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_passwd

FROM scratch

ENV PATH=/bin

COPY jwtpxy /bin/
COPY --from=util /etc_passwd /etc/passwd

WORKDIR /

USER nobody
ENTRYPOINT ["/bin/jwtpxy"]