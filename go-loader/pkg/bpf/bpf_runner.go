package bpf

import (
	"errors"

	libbpf "github.com/aquasecurity/libbpfgo"
)

type probeType int

const (
	KPROBE probeType = iota
	XDP
)

type bpfModuleRunner struct {
	module *libbpf.Module
	probes map[string]*libbpf.BPFProg
	links  []*libbpf.BPFLink
}

func NewRunner(bpfElfPath string) (*bpfModuleRunner, error) {
	bpfModule, err := libbpf.NewModuleFromFile(bpfElfPath)
	if err != nil {
		return nil, err
	}
	err = bpfModule.BPFLoadObject()
	if err != nil {
		return nil, err
	}

	return &bpfModuleRunner{
		module: bpfModule,
		probes: make(map[string]*libbpf.BPFProg),
		links:  make([]*libbpf.BPFLink, 0),
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
		link, err := b.probes[programName].AttachKprobe(attachment)
		if err != nil {
			return err
		}
		b.links = append(b.links, link)
	case XDP:
		link, err := b.probes[programName].AttachXDP(attachment)
		if err != nil {
			return err
		}
		b.links = append(b.links, link)
	}

	return nil
}

func (b *bpfModuleRunner) AttachCgroup(programName, cgroupPath string) error {
	prog, ok := b.probes[programName]
	if !ok {
		return errors.New("program not loaded")
	}

	link, err := prog.AttachCgroup(cgroupPath)
	if err != nil {
		return err
	}
	b.links = append(b.links, link)
	return nil
}

func (b *bpfModuleRunner) AttachRingBuffer(ringBufferName string) (chan []byte, *libbpf.RingBuffer, error) {
	eventsChannel := make(chan []byte)
	rb, err := b.module.InitRingBuf(ringBufferName, eventsChannel)
	if err != nil {
		return nil, nil, err
	}
	return eventsChannel, rb, nil

}

func (b *bpfModuleRunner) GetMap(mapName string) (*libbpf.BPFMap, error) {
	bpfMap, err := b.module.GetMap(mapName)
	if err != nil {
		return nil, err
	}
	return bpfMap, nil
}

func (b *bpfModuleRunner) Close() {
	for _, link := range b.links {
		_ = link.Destroy()
	}
	b.module.Close()
}
