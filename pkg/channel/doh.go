package channel

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/byjanke/ghostlink/pkg/traffic"
)

func init() {
	Register(DoHChannel, func() Channel {
		return &dohChannel{
			normalizer: traffic.NewNormalizer(traffic.HTTPTraffic),
			resolver:   "https://cloudflare-dns.com/dns-query",
			client: &http.Client{
				Timeout: 15 * time.Second,
			},
		}
	}, func() Listener {
		return &dohListener{
			recvCh: make(chan []byte, 256),
			connCh: make(chan *dohServerChannel, 100),
		}
	})
}

type dohChannel struct {
	resolver   string
	domain     string
	normalizer *traffic.Normalizer
	client     *http.Client
	serverAddr string
	directMode bool
}

type dohServerChannel struct {
	recvCh chan []byte
	sendCh chan []byte
}

type dohListener struct {
	server *http.Server
	recvCh chan []byte
	connCh chan *dohServerChannel
}

func (c *dohChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        DoHChannel,
		Name:        "DNS-over-HTTPS Tunnel",
		Description: "Tunnels data through DoH (RFC 8484), completely bypasses DNS monitoring and DPI",
		Capability:  0.96,
	}
}

func (c *dohChannel) Connect(addr string) error {
	if strings.HasPrefix(addr, "http") {
		c.directMode = true
		c.serverAddr = addr
		return nil
	}

	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		c.domain = parts[0]
		c.resolver = parts[1]
		if !strings.HasPrefix(c.resolver, "http") {
			c.resolver = "https://" + c.resolver + "/dns-query"
		}
	} else {
		c.domain = addr
	}

	return nil
}

func (c *dohChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()

	if c.directMode {
		return c.sendDirect(data)
	}
	return c.sendViaDoH(data)
}

func (c *dohChannel) sendDirect(data []byte) error {
	encoded := base64.RawURLEncoding.EncodeToString(data)
	body := []byte(`{"data":"` + encoded + `"}`)

	req, err := http.NewRequest("POST", c.serverAddr, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("doh direct request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", traffic.CommonUserAgents[0])

	resp, err := c.client.Do(req)
	if err != nil {
		c.normalizer.RecordSend()
		return fmt.Errorf("doh direct send: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c.normalizer.RecordSend()
	return nil
}

func (c *dohChannel) sendViaDoH(data []byte) error {
	encoded := base64.RawURLEncoding.EncodeToString(data)

	var labels []string
	for i := 0; i < len(encoded); i += 63 {
		end := i + 63
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[i:end])
	}

	fqdn := strings.Join(labels, ".") + "." + c.domain
	dnsQuery := buildRawDNSQuery(fqdn, 16)

	req, err := http.NewRequest("POST", c.resolver, bytes.NewReader(dnsQuery))
	if err != nil {
		return fmt.Errorf("doh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", traffic.CommonUserAgents[0])

	resp, err := c.client.Do(req)
	if err != nil {
		c.normalizer.RecordSend()
		return fmt.Errorf("doh send: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	c.normalizer.RecordSend()
	return nil
}

func (c *dohChannel) Recv() ([]byte, error) {
	if c.directMode {
		return c.recvDirect()
	}
	return c.recvViaDoH()
}

func (c *dohChannel) recvDirect() ([]byte, error) {
	req, err := http.NewRequest("GET", c.serverAddr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", traffic.CommonUserAgents[0])

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh recv: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("doh: empty response")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(string(body))
	if err != nil {
		return body, nil
	}
	return decoded, nil
}

func (c *dohChannel) recvViaDoH() ([]byte, error) {
	pollFQDN := "poll." + c.domain
	dnsQuery := buildRawDNSQuery(pollFQDN, 16)

	req, err := http.NewRequest("POST", c.resolver, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", traffic.CommonUserAgents[0])

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh recv: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseDNSTXTFromWire(body), nil
}

func (c *dohChannel) Close() error {
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
	return nil
}

func (l *dohListener) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		var err error

		switch r.Method {
		case "POST":
			body, err = io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				w.WriteHeader(400)
				return
			}
		case "GET":
			dnsParam := r.URL.Query().Get("dns")
			if dnsParam != "" {
				body, err = base64.RawURLEncoding.DecodeString(dnsParam)
				if err != nil {
					w.WriteHeader(400)
					return
				}
			}
		}

		if len(body) > 0 {
			select {
			case l.recvCh <- body:
			default:
			}
		}

		sc := &dohServerChannel{
			recvCh: l.recvCh,
			sendCh: make(chan []byte, 10),
		}
		select {
		case l.connCh <- sc:
		default:
		}

		var respData []byte
		select {
		case respData = <-sc.sendCh:
		case <-time.After(100 * time.Millisecond):
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Server", "cloudflare")
		if respData != nil {
			encoded := base64.RawURLEncoding.EncodeToString(respData)
			w.Write([]byte(encoded))
		}
	})

	l.server = &http.Server{Addr: addr, Handler: mux}
	go l.server.ListenAndServe()
	return nil
}

func (l *dohListener) Accept() (Channel, net.Addr, error) {
	select {
	case <-l.connCh:
		ch := &dohChannel{
			normalizer: traffic.NewNormalizer(traffic.HTTPTraffic),
			directMode: true,
			client:     &http.Client{Timeout: 15 * time.Second},
		}
		return ch, nil, nil
	case <-time.After(60 * time.Second):
		return nil, nil, fmt.Errorf("doh accept timeout")
	}
}

func (l *dohListener) Close() error {
	if l.server != nil {
		return l.server.Close()
	}
	return nil
}

func buildRawDNSQuery(fqdn string, qtype uint16) []byte {
	var msg []byte

	var randBytes [2]byte
	crand.Read(randBytes[:])
	msg = append(msg, randBytes[:]...)
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0x00, 0x01)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

	for _, label := range strings.Split(fqdn, ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, byte(qtype>>8), byte(qtype&0xFF))
	msg = append(msg, 0x00, 0x01)
	return msg
}

func parseDNSTXTFromWire(resp []byte) []byte {
	if len(resp) < 12 {
		return nil
	}
	anCount := int(resp[6])<<8 | int(resp[7])
	if anCount == 0 {
		return nil
	}

	offset := 12
	for offset < len(resp) && resp[offset] != 0 {
		l := int(resp[offset])
		if l&0xC0 == 0xC0 {
			offset += 2
			goto answers
		}
		offset += l + 1
	}
	if offset < len(resp) && resp[offset] == 0 {
		offset++
	}
	offset += 4

answers:
	for i := 0; i < anCount && offset+10 < len(resp); i++ {
		if resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(resp) && resp[offset] != 0 {
				l := int(resp[offset])
				if l&0xC0 == 0xC0 {
					offset += 2
					break
				}
				offset += l + 1
			}
			if offset < len(resp) && resp[offset] == 0 {
				offset++
			}
		}
		if offset+10 > len(resp) {
			break
		}
		rtype := int(resp[offset])<<8 | int(resp[offset+1])
		offset += 8
		rdlen := int(resp[offset])<<8 | int(resp[offset+1])
		offset += 2

		if rtype == 16 && rdlen > 0 && offset+rdlen <= len(resp) {
			rdata := resp[offset : offset+rdlen]
			if len(rdata) > 1 {
				txtLen := int(rdata[0])
				if txtLen+1 <= len(rdata) {
					txt := string(rdata[1 : txtLen+1])
					decoded, err := base64.RawURLEncoding.DecodeString(txt)
					if err == nil {
						return decoded
					}
				}
			}
		}
		offset += rdlen
	}
	return nil
}

var _ Channel = (*dohChannel)(nil)
var _ Listener = (*dohListener)(nil)

var dohRandMu sync.Mutex
