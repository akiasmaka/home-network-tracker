package probeRunnerdo_unlinkat

import (
	bpf "github.com/aquasecurity/libbpfgo"
)

type probeType int

const  (
	KPROBE probeType = iota
	XDP
)

type bpfModuleRunner struct {
	module *bpf.Module
	probes map[string]*bpf.BPFProg
}

func NewRunner(bpfElfPath string) (*bpfModuleRunner, error) {
	bpfModule, err := bpf.NewModuleFromFile(bpfElfPath)
	if err != nil {
		return nil, err
	}
	err = bpfModule.BPFLoadObject()
	if err != nil {
		return nil, err
	}

	return &bpfModuleRunner{
		module: bpfModule,
		probes: make(map[string]*bpf.BPFProg),
	}, nil
}

func (b *bpfModuleRunner) LoadProgram(programName string) error {
	prog, err := b.module.GetProgram(programName)
	if err != nil {
		return err
	}
	b.probes[programName] = prog
	return nil
}

func (b *bpfModuleRunner) AttachProbe(programName, attachment string, probeType probeType) error {
	switch probeType {
	case KPROBE:
		_, err := b.probes[programName].AttachKprobe(attachment)
		if err != nil {
			return err
		}
	case XDP:
		_, err := b.probes[programName].AttachXDP(attachment)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *bpfModuleRunner) AttachRingBuffer(ringBufferName string) (chan []byte, *bpf.RingBuffer, error) {
	eventsChannel := make(chan []byte)
	rb, err := b.module.InitRingBuf(ringBufferName, eventsChannel)
	if err != nil {
		return nil, nil, err
	}
	return eventsChannel, rb, nil

}

func (b *bpfModuleRunner) Close() {
	b.module.Close()
}