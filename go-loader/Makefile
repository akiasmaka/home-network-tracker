BASEDIR = $(abspath ../)

OUTPUT = ../build

LIBBPF_OBJ = $(abspath $(OUTPUT)/libbpf/libbpf.a)
LIBBPF_SRC = $(abspath ../libbpf/src)

CC = clang
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
	GOARCH=amd64 \
	go build \
	-tags netgo \
	-ldflags $(CGO_EXTLDFLAGS) \
	-o go-loader ./cmd/main.go
