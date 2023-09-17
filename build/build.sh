set -ex

function build_image() {
    docker build -t builder -f $(pwd)/build/Dockerfile.builder $(pwd)/libbpf
}

function fail() {
    echo $1
    exit 1
}

BUILD_PROBE=0
GENERATE_CMAKE=0

while [[ $# -ge 1 ]]
do
    case $1 in
        --rebuild-image)
            shift
            build_image
            ;;
        --generate-cmake)
            shift
            GENERATE_CMAKE=1
            ;;
        --build-probe)
            shift
            BUILD_PROBE=1
            ;;
        *)
            fail "unknown build argument"
            ;;
    esac
done

WORKDIR=$(pwd)

if (( $GENERATE_CMAKE  == 1 ))
then
    docker run -it --rm -w $WORKDIR/build \
        -v $WORKDIR:$WORKDIR \
        builder cmake ../probe
else
    echo "Skipping cmake generation"
fi

if (( $BUILD_PROBE  == 1 ))
then
    docker run -it --rm -w $WORKDIR/build \
        -v $WORKDIR:$WORKDIR \
        builder make
else
    echo "Skipping probe build"
fi
    