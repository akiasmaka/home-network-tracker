set -ex

function build_image() {
    docker build -t builder -f $(pwd)/build/Dockerfile.builder $(pwd)
}

function fail() {
    echo $1
    exit 1
}

BUILD_PROBE=0
GENERATE_CMAKE=0
BUILD_LOADER=0
BUILD_WEB=0
BUILD_APP_IMAGE=0

APP_IMAGE_NAME=homenetworktracker
APP_IMAGE_TAG=latest

while [[ $# -ge 1 ]]
do
    case $1 in
        --all)
            shift
            GENERATE_CMAKE=1
            BUILD_PROBE=1
            BUILD_LOADER=1
            BUILD_WEB=1
            BUILD_APP_IMAGE=1
            build_image
            ;;
        --build-app-image)
            shift
            BUILD_APP_IMAGE=1
            ;;
        --image-tag)
            shift
            [[ $# -ge 1 ]] || fail "--image-tag requires a value"
            APP_IMAGE_TAG=$1
            shift
            ;;
        --build-builder-image)
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
        --build-loader)
            shift
            BUILD_LOADER=1
            ;;
        --build-web)
            shift
            BUILD_WEB=1
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
    
if (( $BUILD_LOADER  == 1 ))
then
    docker run -it --rm -w $WORKDIR/go-loader \
        -v $WORKDIR:$WORKDIR \
        -v $WORKDIR/build/go-cache:/root/.cache/go-build \
        builder make
else
    echo "Skipping loader build"
fi

if (( $BUILD_WEB  == 1 ))
then
    rm -rf $WORKDIR/web/node_modules
    docker run -it --rm -w $WORKDIR/web \
        -v $WORKDIR:$WORKDIR \
        --user $(id -u):$(id -g) \
        -e HOME=/tmp \
        -e PNPM_STORE_DIR=/tmp/.pnpm-store \
        node:20 corepack pnpm install --store-dir /tmp/.pnpm-store
    docker run -it --rm -w $WORKDIR/web \
        -v $WORKDIR:$WORKDIR \
        --user $(id -u):$(id -g) \
        -e HOME=/tmp \
        -e PNPM_STORE_DIR=/tmp/.pnpm-store \
        node:20 corepack pnpm build
else
    echo "Skipping web build"
fi

if (( $BUILD_APP_IMAGE == 1 ))
then
    [[ -f $WORKDIR/build/xdp.bpf.o ]] || fail "missing $WORKDIR/build/xdp.bpf.o (run ./build/build.sh --build-probe)"
    [[ -f $WORKDIR/go-loader/go-loader ]] || fail "missing $WORKDIR/go-loader/go-loader (run ./build/build.sh --build-loader)"

    docker build --pull --rm \
        -f $WORKDIR/Dockerfile \
        -t ${APP_IMAGE_NAME}:${APP_IMAGE_TAG} \
        $WORKDIR
else
    echo "Skipping app image build"
fi