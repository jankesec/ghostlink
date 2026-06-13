package forward

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Tunnel struct {
	ID       uint32
	Local    string
	Remote   string
	listener net.Listener
	conns    map[uint32]net.Conn
	mu       sync.Mutex
	nextID   uint32
	onData   func(tunnelID, connID uint32, data []byte)
	onClose  func(tunnelID, connID uint32)
}

func NewTunnel(id uint32, localAddr, remoteAddr string) *Tunnel {
	return &Tunnel{
		ID:     id,
		Local:  localAddr,
		Remote: remoteAddr,
		conns:  make(map[uint32]net.Conn),
	}
}

func (t *Tunnel) SetCallbacks(onData func(uint32, uint32, []byte), onClose func(uint32, uint32)) {
	t.onData = onData
	t.onClose = onClose
}

func (t *Tunnel) Listen() error {
	l, err := net.Listen("tcp", t.Local)
	if err != nil {
		return fmt.Errorf("forward listen %s: %w", t.Local, err)
	}
	t.listener = l

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			t.mu.Lock()
			cid := t.nextID
			t.nextID++
			t.conns[cid] = conn
			t.mu.Unlock()

			go t.handleConn(conn, cid)
		}
	}()

	return nil
}

func (t *Tunnel) handleConn(conn net.Conn, cid uint32) {
	defer func() {
		conn.Close()
		t.mu.Lock()
		delete(t.conns, cid)
		t.mu.Unlock()
		if t.onClose != nil {
			t.onClose(t.ID, cid)
		}
	}()

	buf := make([]byte, 32768)
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if t.onData != nil && n > 0 {
			t.onData(t.ID, cid, buf[:n])
		}
	}
}

func (t *Tunnel) WriteToConn(cid uint32, data []byte) error {
	t.mu.Lock()
	conn, ok := t.conns[cid]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("connection %d not found", cid)
	}
	_, err := conn.Write(data)
	return err
}

func (t *Tunnel) DialAndConnect(cid uint32) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", t.Remote, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", t.Remote, err)
	}
	t.mu.Lock()
	t.conns[cid] = conn
	t.mu.Unlock()
	return conn, nil
}

func (t *Tunnel) ReadFromConn(cid uint32, buf []byte) (int, error) {
	t.mu.Lock()
	conn, ok := t.conns[cid]
	t.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("connection %d not found", cid)
	}
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	return conn.Read(buf)
}

func (t *Tunnel) CloseConn(cid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if conn, ok := t.conns[cid]; ok {
		conn.Close()
		delete(t.conns, cid)
	}
}

func (t *Tunnel) Close() {
	if t.listener != nil {
		t.listener.Close()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, conn := range t.conns {
		conn.Close()
	}
	t.conns = make(map[uint32]net.Conn)
}

func (t *Tunnel) WriteToConnDirect(cid uint32, data []byte) (int, error) {
	t.mu.Lock()
	conn, ok := t.conns[cid]
	t.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("connection %d not found", cid)
	}
	return conn.Write(data)
}

func (t *Tunnel) ReadConn(cid uint32, buf []byte) (int, error) {
	t.mu.Lock()
	conn, ok := t.conns[cid]
	t.mu.Unlock()
	if !ok {
		return 0, fmt.Errorf("connection %d not found", cid)
	}
	return conn.Read(buf)
}

func Copy(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}
