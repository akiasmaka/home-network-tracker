FROM alpine:3.21

WORKDIR /tracker

COPY ./build/xdp.bpf.o ./build/xdp.bpf.o
COPY ./build/dns_sniffer.bpf.o ./build/dns_sniffer.bpf.o
COPY ./go-loader/go-loader .
COPY ./web/dist/ ./web/dist/

ENTRYPOINT [ "./go-loader" ]