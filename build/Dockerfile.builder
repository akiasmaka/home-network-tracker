FROM golang:1.20.7

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential zlib1g-dev libelf-dev clang cmake libc6-dev-i386

CMD ["/bin/bash"]