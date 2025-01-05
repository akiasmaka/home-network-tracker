package network

import (
	"bytes"
	"encoding/binary"
	"net"
)

const (
	IPV4 = 4
	IPV6 = 6
)

type IPKey struct {
	Saddr string `json:"saddr"`
	Daddr string `json:"daddr"`
	Type  int    `json:"type"`
}

type IPv4 struct {
	Saddr uint32 `json:"saddr"`
	Daddr uint32 `json:"daddr"`
}

type In6Addr struct {
	Addr [16]byte `json:"addr"`
}

type IPv6 struct {
	Saddr In6Addr `json:"saddr"`
	Daddr In6Addr `json:"daddr"`
}

func (k IPv4) String() string {
	return IntToIPv4(k.Saddr).String() + " -> " + IntToIPv4(k.Daddr).String()
}

func (k IPv6) String() string {
	return net.IP(k.Saddr.Addr[:]).String() + " -> " + net.IP(k.Daddr.Addr[:]).String()
}

func IntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, ipaddr)
	return ip
}

func ParseIPv4Key(key []byte) (IPv4, error) {
	var d IPv4
	r := bytes.NewReader(key)
	err := binary.Read(r, binary.BigEndian, &d)
	return d, err
}

func AnyIpToString(ip any) string {
	switch ip := ip.(type) {
	case IPv4:
		return ip.String()
	case IPv6:
		return ip.String()
	default:
		return ""
	}
}

func GenericToIp(ip any) IPKey {
	switch ip := ip.(type) {
	case IPv4:
		return IPKey{Type: IPV4, Saddr: IntToIPv4(ip.Saddr).String(), Daddr: IntToIPv4(ip.Daddr).String()}
	case IPv6:
		return IPKey{Type: IPV6, Saddr: net.IP(ip.Saddr.Addr[:]).String(), Daddr: net.IP(ip.Daddr.Addr[:]).String()}
	default:
		return IPKey{}
	}
}
