package network

import (
	"bytes"
	"encoding/binary"
	"net"
)

type IPv4Key struct {
	Saddr uint32 `json:"saddr"`
	Daddr uint32 `json:"daddr"`
}

type In6Addr struct {
	Addr [16]byte `json:"addr"`
}

type IPv6Key struct {
	Saddr In6Addr `json:"saddr"`
	Daddr In6Addr `json:"daddr"`
}

func (k IPv4Key) String() string {
	return IntToIPv4(k.Saddr).String() + " -> " + IntToIPv4(k.Daddr).String()
}

func IntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, ipaddr)
	return ip
}

func ParseIPv4Key(key []byte) (IPv4Key, error) {
	var d IPv4Key
	r := bytes.NewReader(key)
	err := binary.Read(r, binary.BigEndian, &d)
	return d, err
}
