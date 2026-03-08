package resolver

import (
	"context"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/zap"
)

const (
	maxBPFHostnameLen = 64 // Keep short hostnames to reduce memory use
	SO_ATTACH_BPF     = 50 // From linux/socket.h
	dnsCacheTTL       = 1 * time.Hour
)

type dnsCacheEntry struct {
	hostname  string
	timestamp time.Time
}

// DNSSniffer loads and manages the DNS sniffer BPF program
type DNSSniffer struct {
	module   *bpf.Module
	prog     *bpf.BPFProg
	resolver *Resolver
	logger   *zap.Logger
	iface    string
	sockFd   int
	cache    sync.Map
}

// NewDNSSniffer creates a new DNS sniffer
func NewDNSSniffer(resolver *Resolver, iface string, logger *zap.Logger) *DNSSniffer {
	return &DNSSniffer{
		resolver: resolver,
		logger:   logger,
		iface:    iface,
		sockFd:   -1,
	}
}

// Start loads the BPF program and attaches it to a socket
func (s *DNSSniffer) Start(ctx context.Context, bpfPath string) error {
	// Load BPF module
	module, err := bpf.NewModuleFromFile(bpfPath)
	if err != nil {
		return err
	}
	s.module = module

	if err := module.BPFLoadObject(); err != nil {
		module.Close()
		return err
	}

	// Get the program
	prog, err := module.GetProgram("dns_filter")
	if err != nil {
		module.Close()
		return err
	}
	s.prog = prog

	// Create raw socket and attach BPF program
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		module.Close()
		return err
	}
	s.sockFd = fd

	// Get interface index
	iface, err := net.InterfaceByName(s.iface)
	if err != nil {
		syscall.Close(fd)
		module.Close()
		return err
	}

	// Bind to interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		module.Close()
		return err
	}

	// Attach BPF program to socket
	progFd := prog.FileDescriptor()
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_ATTACH_BPF, progFd); err != nil {
		syscall.Close(fd)
		module.Close()
		return err
	}

	s.logger.Info("DNS sniffer BPF program loaded and attached",
		zap.String("interface", s.iface),
		zap.String("bpf_path", bpfPath))

	// Start background goroutine to consume packets (triggers BPF execution)
	go s.run(ctx)

	return nil
}

// run consumes packets from the socket to trigger BPF program execution
func (s *DNSSniffer) run(ctx context.Context) {
	buf := make([]byte, 65536)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("DNS sniffer stopping")
			s.Stop()
			return
		default:
		}

		// Set read timeout
		syscall.SetsockoptTimeval(s.sockFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
			&syscall.Timeval{Sec: 1})

		// Read packet (BPF program filters UDP/53 for us)
		n, _, err := syscall.Recvfrom(s.sockFd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			// Ignore other errors, keep running
			continue
		}

		if n > 0 {
			s.processPacket(buf[:n])
		}
	}
}

// LookupV4 looks up a hostname for an IPv4 address from the BPF cache
func (s *DNSSniffer) LookupV4(ip net.IP) (string, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}

	return s.lookupCache(v4.String())
}

// LookupV6 looks up a hostname for an IPv6 address from the BPF cache
func (s *DNSSniffer) LookupV6(ip net.IP) (string, bool) {
	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}

	return s.lookupCache(v6.String())
}

// Lookup looks up a hostname for any IP address
func (s *DNSSniffer) Lookup(ipStr string) (string, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", false
	}

	if v4 := ip.To4(); v4 != nil {
		return s.LookupV4(ip)
	}
	return s.LookupV6(ip)
}

// Stop closes the sniffer
func (s *DNSSniffer) Stop() {
	if s.sockFd >= 0 {
		syscall.Close(s.sockFd)
		s.sockFd = -1
	}
	if s.module != nil {
		s.module.Close()
		s.module = nil
	}
}

func (s *DNSSniffer) lookupCache(key string) (string, bool) {
	if entryRaw, ok := s.cache.Load(key); ok {
		entry := entryRaw.(dnsCacheEntry)
		if time.Since(entry.timestamp) <= dnsCacheTTL && entry.hostname != "" {
			s.logger.Debug("DNS cache hit", zap.String("ip", key), zap.String("hostname", entry.hostname))
			return entry.hostname, true
		}
		s.cache.Delete(key)
	}
	return "", false
}

func (s *DNSSniffer) storeCache(ip net.IP, hostname string) {
	if ip == nil || hostname == "" {
		return
	}

	if len(hostname) > maxBPFHostnameLen-1 {
		hostname = hostname[:maxBPFHostnameLen-1]
	}

	s.cache.Store(ip.String(), dnsCacheEntry{
		hostname:  hostname,
		timestamp: time.Now(),
	})
}

func (s *DNSSniffer) processPacket(packet []byte) {
	dnsPayload := parseUDPDNSPayload(packet)
	if dnsPayload == nil {
		return
	}

	hostname, answers := parseDNSResponse(dnsPayload)
	if hostname == "" || len(answers) == 0 {
		return
	}

	for _, ip := range answers {
		s.storeCache(ip, hostname)
	}
}

func parseUDPDNSPayload(packet []byte) []byte {
	if len(packet) == 0 {
		return nil
	}

	pkt := gopacket.NewPacket(packet, layers.LayerTypeEthernet, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})
	if pkt.ErrorLayer() != nil {
		return nil
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}

	udp := udpLayer.(*layers.UDP)
	if udp.SrcPort != 53 {
		return nil
	}

	return udp.Payload
}

func parseDNSResponse(msg []byte) (string, []net.IP) {
	var parsed dns.Msg
	parsed.Data = msg
	if err := parsed.Unpack(); err != nil {
		return "", nil
	}

	if !parsed.Response || parsed.Rcode != dns.RcodeSuccess {
		return "", nil
	}

	if len(parsed.Question) == 0 || len(parsed.Answer) == 0 {
		return "", nil
	}

	qname := strings.TrimSuffix(parsed.Question[0].Header().Name, ".")
	if qname == "" {
		return "", nil
	}

	answers := make([]net.IP, 0, 2)
	for _, rr := range parsed.Answer {
		switch v := rr.(type) {
		case *dns.A:
			addr := v.A.Addr
			if addr.Is4() {
				ip4 := addr.As4()
				answers = append(answers, net.IP(ip4[:]))
			}
		case *dns.AAAA:
			addr := v.AAAA.Addr
			if addr.Is6() {
				ip6 := addr.As16()
				answers = append(answers, net.IP(ip6[:]))
			}
		}
	}

	if len(answers) == 0 {
		return "", nil
	}

	return qname, answers
}

// htons converts a uint16 from host to network byte order
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
