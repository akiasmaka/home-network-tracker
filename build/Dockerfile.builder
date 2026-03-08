FROM golang:1.25.7-bookworm

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential zlib1g-dev libelf-dev libdw-dev libzstd-dev clang cmake libc6-dev-i386

CMD ["/bin/bash"]