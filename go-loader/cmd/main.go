package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan bool, 1)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()

	bpfModule, err := bpf.NewModuleFromFile("../build/kprobe.bpf.o")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	prog, err := bpfModule.GetProgram("do_unlinkat")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	funcName := "do_unlinkat"
	_, err = prog.AttachKprobe(funcName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("rb", eventsChannel)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rb.Poll(300)
	defer rb.Stop()
	for {
		select {
		case eventBytes := <-eventsChannel:
			pid := int(binary.LittleEndian.Uint32(eventBytes[0:4]))
			fmt.Println("Got do_unlinkat entry process pid: ", pid)
		case <-done:
			fmt.Println("Exit received")
			os.Exit(0)
		}
	}
}
