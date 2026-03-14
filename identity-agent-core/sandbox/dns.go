package sandbox

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

const (
	dnsHeaderSize    = 12
	dnsTypeA         = 1
	dnsTypeAAAA      = 28
	dnsClassIN       = 1
	dnsMaxPacketSize = 512
)

type DNSQuery struct {
	Domain     string
	QueryType  uint16
	InstanceID string
	Timestamp  time.Time
}

type DNSLogCallback func(query DNSQuery)

type DNSForwarder struct {
	listenAddr  string
	upstream    string
	conn        *net.UDPConn
	logCallback DNSLogCallback
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	running     bool
}

func NewDNSForwarder(listenAddr string, upstream string, logCallback DNSLogCallback) *DNSForwarder {
	if upstream == "" {
		upstream = "8.8.8.8:53"
	}
	return &DNSForwarder{
		listenAddr:  listenAddr,
		upstream:    upstream,
		logCallback: logCallback,
		stopCh:      make(chan struct{}),
	}
}

func (d *DNSForwarder) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return fmt.Errorf("DNS forwarder already running")
	}

	addr, err := net.ResolveUDPAddr("udp", d.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve DNS listen address: %w", err)
	}

	d.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start DNS listener on %s: %w", d.listenAddr, err)
	}

	d.running = true
	d.wg.Add(1)
	go d.serve()

	log.Printf("[sandbox-dns] DNS forwarder listening on %s, upstream: %s", d.listenAddr, d.upstream)
	return nil
}

func (d *DNSForwarder) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.running {
		return
	}

	close(d.stopCh)
	if d.conn != nil {
		d.conn.Close()
	}
	d.wg.Wait()
	d.running = false
	log.Printf("[sandbox-dns] DNS forwarder stopped")
}

func (d *DNSForwarder) ListenAddr() string {
	if d.conn != nil {
		return d.conn.LocalAddr().String()
	}
	return d.listenAddr
}

func (d *DNSForwarder) serve() {
	defer d.wg.Done()
	buf := make([]byte, dnsMaxPacketSize)

	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		d.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-d.stopCh:
				return
			default:
				log.Printf("[sandbox-dns] Read error: %v", err)
				continue
			}
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		go d.handleQuery(packet, clientAddr)
	}
}

func (d *DNSForwarder) handleQuery(packet []byte, clientAddr *net.UDPAddr) {
	domain, qtype := parseDNSQuestion(packet)
	if domain != "" && d.logCallback != nil {
		d.logCallback(DNSQuery{
			Domain:    domain,
			QueryType: qtype,
			Timestamp: time.Now(),
		})
	}

	upstreamAddr, err := net.ResolveUDPAddr("udp", d.upstream)
	if err != nil {
		log.Printf("[sandbox-dns] Failed to resolve upstream %s: %v", d.upstream, err)
		return
	}

	upConn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		log.Printf("[sandbox-dns] Failed to connect to upstream: %v", err)
		return
	}
	defer upConn.Close()

	upConn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := upConn.Write(packet); err != nil {
		log.Printf("[sandbox-dns] Failed to forward query to upstream: %v", err)
		return
	}

	response := make([]byte, dnsMaxPacketSize)
	n, err := upConn.Read(response)
	if err != nil {
		log.Printf("[sandbox-dns] Failed to read upstream response: %v", err)
		return
	}

	if _, err := d.conn.WriteToUDP(response[:n], clientAddr); err != nil {
		log.Printf("[sandbox-dns] Failed to send response to client: %v", err)
	}
}

func parseDNSQuestion(packet []byte) (string, uint16) {
	if len(packet) < dnsHeaderSize+5 {
		return "", 0
	}

	offset := dnsHeaderSize
	var domain string
	for offset < len(packet) {
		labelLen := int(packet[offset])
		if labelLen == 0 {
			offset++
			break
		}
		if offset+1+labelLen > len(packet) {
			return "", 0
		}
		if domain != "" {
			domain += "."
		}
		domain += string(packet[offset+1 : offset+1+labelLen])
		offset += 1 + labelLen
	}

	if offset+4 > len(packet) {
		return domain, 0
	}

	qtype := uint16(packet[offset])<<8 | uint16(packet[offset+1])
	return domain, qtype
}
