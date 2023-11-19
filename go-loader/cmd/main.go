package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	probeRunner "github.com/akiasmaka/home-network-tracker/go-loader/pkg/bpf"
	bpf "github.com/aquasecurity/libbpfgo"
)

func run() int {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()

	bpfRunner, err := probeRunner.NewRunner("build/kprobe.bpf.o")
	if err != nil {
		fmt.Println(err)
		return 1
	}

	err = bpfRunner.LoadProgram("do_unlinkat")
	if err != nil {
		fmt.Println(err)
		return 1
	}

	bpfRunner.AttachProbe("do_unlinkat", "do_unlinkat", probeRunner.KPROBE)
	if err != nil {
		fmt.Println(err)
		return 1
	}

	xpdRunner, err := probeRunner.NewRunner("build/xdp.bpf.o")
	if err != nil {
		fmt.Println(err)
		return 1
	}

	err = xpdRunner.LoadProgram("xdp_count_type")
	if err != nil {
		fmt.Println(err)
		return 1
	}

	xpdRunner.AttachProbe("xdp_count_type", "enp3s0", probeRunner.XDP)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer xpdRunner.Close()

	eventsChannel, rb, err := bpfRunner.AttachRingBuffer("rb")

	return listenToEvents(rb, eventsChannel, done)
}

func listenToEvents(rb *bpf.RingBuffer, eventsChannel chan []byte, done chan bool) int {
	rb.Poll(300)
	defer rb.Stop()
	for {
		select {
		case eventBytes := <-eventsChannel:
			pid := int(binary.LittleEndian.Uint32(eventBytes[0:4]))
			fmt.Println("Got do_unlinkat entry process pid: ", pid)
		case <-done:
			fmt.Println("Exit received")
			return 0
		}
	}
}

func main() {
	os.Exit(run())
}
