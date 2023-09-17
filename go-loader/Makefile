BASEDIR = $(abspath ../)

OUTPUT = ../build

export LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf/libbpf.a)
export LIBBPF_SRC = $(abspath ../libbpf/src)
CLANG = clang
CC = $(CLANG)
GO = go
ARCH = amd64

CFLAGS = -g -O2 -Wall -fpie -I$(abspath ../common)

CGO_CFLAGS = "-I$(abspath $(OUTPUT)) -I$(abspath ../build/libbpf)"
CGO_LDFLAGS = "-lelf -lz $(LIBBPF_OBJ)"
CGO_EXTLDFLAGS = '-w -extldflags "-static"'


all: go-loader

## tracker
.PHONY: go-loader
go-loader: $(OUTPUT)/kprobe.bpf.o
	CC=$(CLANG) \
		CGO_CFLAGS=$(CGO_CFLAGS) \
		CGO_LDFLAGS=$(CGO_LDFLAGS) \
		GOOS=linux \
		GOARCH=$(ARCH) \
		$(GO) build \
		-tags netgo -ldflags $(CGO_EXTLDFLAGS) \
		-o go-loader ./cmd/main.go
