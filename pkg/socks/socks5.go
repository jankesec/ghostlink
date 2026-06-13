package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Tunnel struct {
	ListenAddr string
	conns      map[uint32]net.Conn
	mu         sync.Mutex
	nextID     uint32
	listener   net.Listener
	onConnect  func(connID uint32, addr string)
	onData     func(connID uint32, data []byte)
	onClose    func(connID uint32)
}

func NewTunnel(listenAddr string) *Tunnel {
	return &Tunnel{
		ListenAddr: listenAddr,
		conns:      make(map[uint32]net.Conn),
	}
}

func (t *Tunnel) SetCallbacks(
	onConnect func(connID uint32, addr string),
	onData func(connID uint32, data []byte),
	onClose func(connID uint32),
) {
	t.onConnect = onConnect
	t.onData = onData
	t.onClose = onClose
}

func (t *Tunnel) Listen() error {
	ln, err := net.Listen("tcp", t.ListenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	t.listener = ln
	go t.acceptLoop()
	return nil
}

func (t *Tunnel) acceptLoop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		t.mu.Lock()
		cid := t.nextID
		t.nextID++
		t.conns[cid] = conn
		t.mu.Unlock()

		go t.handleClient(conn, cid)
	}
}

func (t *Tunnel) handleClient(conn net.Conn, cid uint32) {
	defer func() {
		conn.Close()
		t.mu.Lock()
		delete(t.conns, cid)
		t.mu.Unlock()
		if t.onClose != nil {
			t.onClose(cid)
		}
	}()

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	conn.Write([]byte{0x05, 0x00})

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var targetAddr string
	switch reqHeader[3] {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		targetAddr = net.IP(ipBuf).String()
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		targetAddr = string(domainBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		targetAddr = net.IP(ipBuf).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	targetAddr = fmt.Sprintf("%s:%d", targetAddr, port)

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	conn.SetReadDeadline(time.Time{})

	if t.onConnect != nil {
		t.onConnect(cid, targetAddr)
	}

	buf := make([]byte, 32768)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if t.onData != nil && n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			t.onData(cid, data)
		}
	}
}

func (t *Tunnel) WriteToConn(cid uint32, data []byte) error {
	t.mu.Lock()
	conn, ok := t.conns[cid]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("socks5 conn %d not found", cid)
	}
	_, err := conn.Write(data)
	return err
}

func (t *Tunnel) CloseConn(cid uint32) {
	t.mu.Lock()
	conn, ok := t.conns[cid]
	if ok {
		conn.Close()
		delete(t.conns, cid)
	}
	t.mu.Unlock()
}

func (t *Tunnel) Close() {
	if t.listener != nil {
		t.listener.Close()
	}
	t.mu.Lock()
	for _, c := range t.conns {
		c.Close()
	}
	t.conns = make(map[uint32]net.Conn)
	t.mu.Unlock()
}

func HandleSocksConnect(targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks5 dial %s: %w", targetAddr, err)
	}
	return conn, nil
}

func RelayRemote(conn net.Conn, send func([]byte), done func()) {
	defer done()
	buf := make([]byte, 32768)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			send(data)
		}
	}
}

var _ = log.Printf
