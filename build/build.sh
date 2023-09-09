set -ex

function build_image() {
    docker build -t builder -f $(pwd)/build/Dockerfile.builder $(pwd)/libbpf
}

function fail() {
    echo $1
    exit 1
}

while [[ $# -ge 1 ]]
do
    case $1 in
        --rebuild-image)
            shift
            build_image
            ;;
        *)
            fail "unknown build argument"
            ;;
    esac
done

docker run -it --rm -w $(pwd)/libbpf/src \
        -v $(pwd):$(pwd) \
        builder /bin/bash -c  NO_PKG_CONFIG=1 make 

    