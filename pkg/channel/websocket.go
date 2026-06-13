package channel

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
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
	Register(WebSocketChannel, func() Channel {
		return &wsChannel{
			normalizer: traffic.NewNormalizer(traffic.HTTPTraffic),
		}
	}, func() Listener {
		return &wsListener{
			connCh: make(chan *wsChannel, 100),
		}
	})
}

const wsHandshakeTimeout = 10 * time.Second

type wsChannel struct {
	conn       net.Conn
	normalizer *traffic.Normalizer
	mu         sync.Mutex
	isServer   bool
}

type wsListener struct {
	listener net.Listener
	server   *http.Server
	connCh   chan *wsChannel
}

func (c *wsChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        WebSocketChannel,
		Name:        "WebSocket Tunnel",
		Description: "Bidirectional data channel over WebSocket, blends with modern web application traffic",
		Capability:  0.92,
	}
}

func (c *wsChannel) Connect(addr string) error {
	host := addr
	if strings.HasPrefix(host, "ws://") {
		host = host[5:]
	} else if strings.HasPrefix(host, "http://") {
		host = host[7:]
	}

	conn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}

	keyBytes := make([]byte, 16)
	rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	httpHost := host
	if idx := strings.LastIndex(httpHost, ":"); idx > 0 {
		httpHost = httpHost[:idx]
	}

	req := fmt.Sprintf("GET /stream HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"User-Agent: %s\r\n"+
		"Origin: https://%s\r\n"+
		"\r\n", httpHost, wsKey, traffic.CommonUserAgents[0], httpHost)

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return fmt.Errorf("ws handshake write: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(wsHandshakeTimeout))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("ws handshake read: %w", err)
	}
	resp.Body.Close()
	conn.SetReadDeadline(time.Time{})

	if resp.StatusCode != 101 {
		conn.Close()
		return fmt.Errorf("ws handshake rejected: %d", resp.StatusCode)
	}

	c.conn = conn
	c.isServer = false
	return nil
}

func (c *wsChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()
	c.mu.Lock()
	defer c.mu.Unlock()

	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	frame := buildWSFrame(data, !c.isServer)
	_, err := c.conn.Write(frame)
	c.normalizer.RecordSend()
	return err
}

func (c *wsChannel) Recv() ([]byte, error) {
	return readWSFrame(c.conn)
}

func (c *wsChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (l *wsListener) Listen(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Server", "nginx/1.24.0")
			w.Write([]byte("<html><body><h1>OK</h1></body></html>"))
			return
		}

		wsKey := r.Header.Get("Sec-WebSocket-Key")
		acceptKey := computeWSAccept(wsKey)

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "websocket not supported", 500)
			return
		}

		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		_ = buf

		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + acceptKey + "\r\n" +
			"Server: nginx/1.24.0\r\n" +
			"\r\n"
		conn.Write([]byte(resp))

		ch := &wsChannel{
			conn:       conn,
			normalizer: traffic.NewNormalizer(traffic.HTTPTraffic),
			isServer:   true,
		}

		select {
		case l.connCh <- ch:
		default:
			conn.Close()
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx/1.24.0")
		w.Write([]byte("<html><body><h1>OK</h1></body></html>"))
	})

	l.server = &http.Server{Addr: addr, Handler: mux}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("ws listen: %w", err)
	}
	l.listener = ln
	go l.server.Serve(ln)
	return nil
}

func (l *wsListener) Accept() (Channel, net.Addr, error) {
	select {
	case ch := <-l.connCh:
		addr := ch.conn.RemoteAddr()
		return ch, addr, nil
	case <-time.After(60 * time.Second):
		return nil, nil, fmt.Errorf("ws accept timeout")
	}
}

func (l *wsListener) Close() error {
	if l.server != nil {
		l.server.Close()
	}
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func computeWSAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func buildWSFrame(payload []byte, masked bool) []byte {
	var frame []byte
	frame = append(frame, 0x82) // binary, FIN

	plen := len(payload)
	if plen < 126 {
		b := byte(plen)
		if masked {
			b |= 0x80
		}
		frame = append(frame, b)
	} else if plen < 65536 {
		b := byte(126)
		if masked {
			b |= 0x80
		}
		frame = append(frame, b)
		frame = append(frame, byte(plen>>8), byte(plen&0xFF))
	} else {
		b := byte(127)
		if masked {
			b |= 0x80
		}
		frame = append(frame, b)
		lenBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBytes, uint64(plen))
		frame = append(frame, lenBytes...)
	}

	if masked {
		maskKey := make([]byte, 4)
		rand.Read(maskKey)
		frame = append(frame, maskKey...)
		maskedPayload := make([]byte, plen)
		for i := range payload {
			maskedPayload[i] = payload[i] ^ maskKey[i%4]
		}
		frame = append(frame, maskedPayload...)
	} else {
		frame = append(frame, payload...)
	}

	return frame
}

func readWSFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("ws read header: %w", err)
	}

	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(conn, maskKey); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}
