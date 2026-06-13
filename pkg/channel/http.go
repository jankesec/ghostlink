package channel

import (
	"context"
	"crypto/tls"
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
	Register(HTTPChannel, func() Channel {
		return &httpChannel{
			normalizer: traffic.NewNormalizer(traffic.HTTPTraffic),
			client: &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					DisableKeepAlives: false,
				},
			},
		}
	}, func() Listener {
		return &httpListener{
			recvCh: make(chan []byte, 100),
			connCh: make(chan struct{}, 100),
		}
	})
}

type httpChannel struct {
	serverURL  string
	client     *http.Client
	normalizer *traffic.Normalizer
	frontDomain string

	isServer   bool
	listenRecvCh chan []byte
	respDataCh   chan []byte
	mu           sync.Mutex
}

type httpListener struct {
	server *http.Server
	recvCh chan []byte
	connCh chan struct{}
	mu     sync.Mutex
}

func (c *httpChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        HTTPChannel,
		Name:        "HTTP Header Tunnel",
		Description: "Smuggles data in HTTP headers (Cookie, User-Agent, custom headers), blending with web traffic",
		Capability:  0.90,
	}
}

func (c *httpChannel) Connect(addr string) error {
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	c.serverURL = addr
	c.isServer = false

	if c.frontDomain != "" {
		fmt.Printf("[*] domain fronting enabled: SNI=%s (TLS verification may be bypassed for CDN fronting)\n", c.frontDomain)
		tr := &http.Transport{
			DisableKeepAlives: false,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, _ := net.SplitHostPort(addr)

				dialer := &net.Dialer{Timeout: 10 * time.Second}

				ips, err := net.LookupIP(c.frontDomain)
				if err != nil || len(ips) == 0 {
					return nil, fmt.Errorf("front domain resolve: %w", err)
				}

				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
				if err != nil {
					return nil, err
				}

				tlsCfg := &tls.Config{
					ServerName: c.frontDomain,
				}
				tlsConn := tls.Client(conn, tlsCfg)
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					return nil, fmt.Errorf("tls handshake: %w", err)
				}
				return tlsConn, nil
			},
		}

		c.client = &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
		}
	}

	return nil
}

func (c *httpChannel) SetFrontDomain(domain string) {
	c.frontDomain = domain
}

func (c *httpChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()

	if c.isServer {
		c.mu.Lock()
		if c.respDataCh == nil {
			c.mu.Unlock()
			return fmt.Errorf("http server: no response channel for client")
		}
		ch := c.respDataCh
		c.mu.Unlock()
		select {
		case ch <- data:
			return nil
		default:
			return fmt.Errorf("http server: response channel full")
		}
	}

	encoded := base64.RawURLEncoding.EncodeToString(data)
	req, err := http.NewRequest("GET", c.serverURL, nil)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	req.Header.Set("User-Agent", traffic.CommonUserAgents[time.Now().UnixNano()%int64(len(traffic.CommonUserAgents))])
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Cache-Control", "no-cache")
	if len(encoded) > 1 {
		mid := len(encoded) / 2
		req.Header.Set("Cookie", fmt.Sprintf("session=%s; tracking=%s", encoded[:mid], encoded[mid:]))
	} else {
		req.Header.Set("Cookie", fmt.Sprintf("session=%s", encoded))
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.normalizer.RecordSend()
		return fmt.Errorf("http send: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	c.normalizer.RecordSend()
	return nil
}

func (c *httpChannel) Recv() ([]byte, error) {
	if c.isServer {
		if c.listenRecvCh == nil {
			return nil, fmt.Errorf("http server: no receive channel")
		}
		select {
		case data := <-c.listenRecvCh:
			return data, nil
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("http server: recv timeout")
		}
	}

	req, err := http.NewRequest("GET", c.serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http recv request: %w", err)
	}
	req.Header.Set("User-Agent", traffic.CommonUserAgents[0])
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http recv: %w", err)
	}
	defer resp.Body.Close()

	cookieHeader := resp.Header.Get("Set-Cookie")
	if cookieHeader == "" {
		body, _ := io.ReadAll(resp.Body)
		return body, nil
	}
	encoded := extractCookieValue(cookieHeader, "data")
	if encoded == "" {
		body, _ := io.ReadAll(resp.Body)
		return body, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("http decode: %w", err)
	}
	return decoded, nil
}

func (c *httpChannel) Close() error {
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
	return nil
}

func (l *httpListener) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		if cookie != "" {
			sessionVal := extractCookieValue(cookie, "session")
			trackingVal := extractCookieValue(cookie, "tracking")
			combined := sessionVal + trackingVal
			if data, err := base64.RawURLEncoding.DecodeString(combined); err == nil {
				select {
				case l.recvCh <- data:
				default:
				}
			}
		}

		select {
		case l.connCh <- struct{}{}:
		default:
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.24.0")
		w.Write([]byte("<html><body><h1>OK</h1></body></html>"))
	})

	l.server = &http.Server{Addr: addr, Handler: mux}
	go l.server.ListenAndServe()
	return nil
}

func (l *httpListener) Accept() (Channel, net.Addr, error) {
	select {
	case <-l.connCh:
	case <-time.After(30 * time.Second):
	}

	respCh := make(chan []byte, 10)

	ch := &httpChannel{
		normalizer:   traffic.NewNormalizer(traffic.HTTPTraffic),
		client:       &http.Client{Timeout: 30 * time.Second},
		isServer:     true,
		listenRecvCh: l.recvCh,
		respDataCh:   respCh,
	}

	return ch, nil, nil
}

func (l *httpListener) Close() error {
	if l.server != nil {
		return l.server.Close()
	}
	return nil
}

func extractCookieValue(cookieStr, key string) string {
	for _, part := range strings.Split(cookieStr, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, key+"=") {
			return strings.TrimPrefix(part, key+"=")
		}
	}
	return ""
}

func SetHTTPFrontDomain(ch Channel, domain string) {
	if hc, ok := ch.(*httpChannel); ok {
		hc.frontDomain = domain
	}
}
