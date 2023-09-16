FROM ubuntu:20.04

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential zlib1g-dev libelf-dev clang cmake

CMD ["/bin/bash"]