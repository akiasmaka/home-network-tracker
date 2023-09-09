FROM ubuntu:20.04

RUN apt-get update
RUN apt-get install -y build-essential zlib1g-dev libelf-dev clang 

CMD ["/bin/bash"]