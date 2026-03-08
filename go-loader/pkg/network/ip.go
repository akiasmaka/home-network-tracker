package network

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

const (
	IPV4                   = 4
	IPV6                   = 6
	DirectionUnknown uint8 = 0
	DirectionIngress uint8 = 1
	DirectionEgress  uint8 = 2
)

type IPKey struct {
	Saddr     string `json:"saddr"`
	Daddr     string `json:"daddr"`
	IfIndex   uint32 `json:"ifindex"`
	CgroupID  uint64 `json:"cgroupId"`
	Direction uint8  `json:"direction"`
	Proto     uint8  `json:"proto"`
	Type      int    `json:"type"`
}

type IPv4Key struct {
	Saddr     uint32 `json:"saddr"`
	Daddr     uint32 `json:"daddr"`
	IfIndex   uint32 `json:"ifindex"`
	CgroupID  uint64 `json:"cgroupId"`
	Direction uint8  `json:"direction"`
	Proto     uint8  `json:"proto"`
	Pad       [2]byte
}

type In6Addr struct {
	Addr [16]byte `json:"addr"`
}

type IPv6Key struct {
	Saddr     In6Addr `json:"saddr"`
	Daddr     In6Addr `json:"daddr"`
	IfIndex   uint32  `json:"ifindex"`
	CgroupID  uint64  `json:"cgroupId"`
	Direction uint8   `json:"direction"`
	Proto     uint8   `json:"proto"`
	Pad       [2]byte
}

func (k IPv4Key) String() string {
	return IntToIPv4(k.Saddr).String() + " -> " + IntToIPv4(k.Daddr).String()
}

func (k IPv6Key) String() string {
	return net.IP(k.Saddr.Addr[:]).String() + " -> " + net.IP(k.Daddr.Addr[:]).String()
}

func IntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, ipaddr)
	return ip
}

func ParseIPv4Key(key []byte) (IPv4Key, error) {
	var d IPv4Key
	if len(key) < 32 {
		return d, io.ErrUnexpectedEOF
	}
	d.Saddr = binary.BigEndian.Uint32(key[0:4])
	d.Daddr = binary.BigEndian.Uint32(key[4:8])
	d.IfIndex = binary.LittleEndian.Uint32(key[8:12])
	// The C struct is naturally aligned, so cgroup_id starts at offset 16.
	d.CgroupID = binary.LittleEndian.Uint64(key[16:24])
	d.Proto = key[24]
	d.Direction = key[25]
	copy(d.Pad[:], key[26:28])
	return d, nil
}

func ParseIPv6Key(key []byte) (IPv6Key, error) {
	var d IPv6Key
	if len(key) < 56 {
		return d, io.ErrUnexpectedEOF
	}
	copy(d.Saddr.Addr[:], key[0:16])
	copy(d.Daddr.Addr[:], key[16:32])
	d.IfIndex = binary.LittleEndian.Uint32(key[32:36])
	// The C struct is naturally aligned, so cgroup_id starts at offset 40.
	d.CgroupID = binary.LittleEndian.Uint64(key[40:48])
	d.Proto = key[48]
	d.Direction = key[49]
	copy(d.Pad[:], key[50:52])
	return d, nil
}

func GenericToIp(ipKey IPKey) any {
	switch ipKey.Type {
	case IPV4:
		return IPv4Key{
			Saddr:     binary.BigEndian.Uint32(net.ParseIP(ipKey.Saddr).To4()),
			Daddr:     binary.BigEndian.Uint32(net.ParseIP(ipKey.Daddr).To4()),
			IfIndex:   ipKey.IfIndex,
			CgroupID:  ipKey.CgroupID,
			Direction: ipKey.Direction,
			Proto:     ipKey.Proto,
		}
	case IPV6:
		var saddr, daddr In6Addr
		copy(saddr.Addr[:], net.ParseIP(ipKey.Saddr).To16())
		copy(daddr.Addr[:], net.ParseIP(ipKey.Daddr).To16())
		return IPv6Key{
			Saddr:     saddr,
			Daddr:     daddr,
			IfIndex:   ipKey.IfIndex,
			CgroupID:  ipKey.CgroupID,
			Direction: ipKey.Direction,
			Proto:     ipKey.Proto,
		}
	default:
		return nil
	}
}

func IpToKernelKey(ip any) [64]byte {
	var key [64]byte
	switch ip := ip.(type) {
	case IPv4Key:
		binary.BigEndian.PutUint32(key[0:4], ip.Saddr)
		binary.BigEndian.PutUint32(key[4:8], ip.Daddr)
		binary.LittleEndian.PutUint32(key[8:12], ip.IfIndex)
		// Match the aligned C struct layout.
		binary.LittleEndian.PutUint64(key[16:24], ip.CgroupID)
		key[24] = ip.Proto
		key[25] = ip.Direction
	case IPv6Key:
		copy(key[0:16], ip.Saddr.Addr[:])
		copy(key[16:32], ip.Daddr.Addr[:])
		binary.LittleEndian.PutUint32(key[32:36], ip.IfIndex)
		// Match the aligned C struct layout.
		binary.LittleEndian.PutUint64(key[40:48], ip.CgroupID)
		key[48] = ip.Proto
		key[49] = ip.Direction
	}
	return key
}

func NormalizeKernelKey(raw []byte, connType int) ([64]byte, error) {
	var key [64]byte
	switch connType {
	case IPV4:
		if len(raw) < 32 {
			return key, io.ErrUnexpectedEOF
		}
		copy(key[:], raw)
		// Clear alignment/padding bytes that may be non-deterministic in kernel keys.
		for i := 12; i < 16; i++ {
			key[i] = 0
		}
		for i := 26; i < 28; i++ {
			key[i] = 0
		}
		for i := 28; i < 32; i++ {
			key[i] = 0
		}
	case IPV6:
		if len(raw) < 56 {
			return key, io.ErrUnexpectedEOF
		}
		copy(key[:], raw)
		// Clear alignment/padding bytes that may be non-deterministic in kernel keys.
		for i := 36; i < 40; i++ {
			key[i] = 0
		}
		for i := 50; i < 52; i++ {
			key[i] = 0
		}
		for i := 52; i < 56; i++ {
			key[i] = 0
		}
	default:
		return key, errors.New("unknown connection type")
	}
	return key, nil
}

func SetCgroupInKey(key *[64]byte, connType int, cgroupID uint64) error {
	switch connType {
	case IPV4:
		binary.LittleEndian.PutUint64(key[16:24], cgroupID)
	case IPV6:
		binary.LittleEndian.PutUint64(key[40:48], cgroupID)
	default:
		return errors.New("unknown connection type")
	}
	return nil
}

func DirectionLabel(direction uint8) string {
	switch direction {
	case DirectionIngress:
		return "ingress"
	case DirectionEgress:
		return "egress"
	default:
		return "unknown"
	}
}
