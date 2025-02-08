FROM alpine:3.21

WORKDIR /tracker

COPY build/xdp.bpf.o ./build/xdp.bpf.o    

COPY go-loader .

# Set the entry point to execute the Go binary
ENTRYPOINT [ "./go-loader" ]