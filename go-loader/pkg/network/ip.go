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

func GenericToIp(ipKey IPKey) any {
	switch ipKey.Type {
	case IPV4:
		return IPv4{
			Saddr: binary.BigEndian.Uint32(net.ParseIP(ipKey.Saddr).To4()),
			Daddr: binary.BigEndian.Uint32(net.ParseIP(ipKey.Daddr).To4()),
		}
	case IPV6:
		var saddr, daddr In6Addr
		copy(saddr.Addr[:], net.ParseIP(ipKey.Saddr).To16())
		copy(daddr.Addr[:], net.ParseIP(ipKey.Daddr).To16())
		return IPv6{
			Saddr: saddr,
			Daddr: daddr,
		}
	default:
		return nil
	}
}

func IpToKernelKey(ip any) [64]byte {
	var key [64]byte
	switch ip := ip.(type) {
	case IPv4:
		binary.BigEndian.PutUint32(key[0:4], ip.Saddr)
		binary.BigEndian.PutUint32(key[4:8], ip.Daddr)
	case IPv6:
		copy(key[0:16], ip.Saddr.Addr[:])
		copy(key[16:32], ip.Daddr.Addr[:])
	}
	return key
}