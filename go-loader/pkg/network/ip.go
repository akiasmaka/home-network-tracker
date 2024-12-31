package network

import (
	"bytes"
	"encoding/binary"
	"net"
)

type IPv4Key struct {
	Saddr uint32
	Daddr uint32
}

type In6Addr struct {
	Addr [16]byte
}

type IPv6Key struct {
	Saddr In6Addr
	Daddr In6Addr
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
