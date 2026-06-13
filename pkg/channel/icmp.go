package channel

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/byjanke/ghostlink/pkg/traffic"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func init() {
	Register(ICMPChannel, func() Channel {
		return &icmpChannel{
			normalizer: traffic.NewNormalizer(traffic.ICMPTraffic),
			id:         uint16(os.Getpid() & 0xFFFF),
			seq:        1,
		}
	}, func() Listener {
		return &icmpListener{
			recvCh: make(chan []byte, 100),
		}
	})
}

type icmpChannel struct {
	conn       *icmp.PacketConn
	peer       net.Addr
	id         uint16
	seq        uint16
	normalizer *traffic.Normalizer

	isServer   bool
	listenConn *icmp.PacketConn
	clientAddr net.Addr
	recvCh     chan []byte
	mu         sync.Mutex
}

type icmpListener struct {
	conn   *icmp.PacketConn
	recvCh chan []byte
}

func (c *icmpChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        ICMPChannel,
		Name:        "ICMP Tunnel",
		Description: "Hides data in ICMP Echo Request/Reply payloads, blending with normal ping traffic",
		Capability:  0.75,
	}
}

func (c *icmpChannel) Connect(addr string) error {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("icmp listen: %w", err)
	}
	c.conn = conn
	peer, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		conn.Close()
		return fmt.Errorf("icmp resolve: %w", err)
	}
	c.peer = peer
	c.isServer = false
	return nil
}

func (c *icmpChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(c.id),
			Seq:  int(c.seq),
			Data: data,
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("icmp marshal: %w", err)
	}

	if c.isServer {
		if c.listenConn == nil || c.clientAddr == nil {
			return fmt.Errorf("icmp server: not connected to client")
		}
		_, err = c.listenConn.WriteTo(b, c.clientAddr)
		c.seq++
		c.normalizer.RecordSend()
		return err
	}

	_, err = c.conn.WriteTo(b, c.peer)
	c.seq++
	c.normalizer.RecordSend()
	return err
}

func (c *icmpChannel) Recv() ([]byte, error) {
	if c.isServer {
		if c.recvCh == nil {
			return nil, fmt.Errorf("icmp server: no receive channel")
		}
		select {
		case data := <-c.recvCh:
			return data, nil
		case <-time.After(5 * time.Second):
			return nil, fmt.Errorf("icmp server: recv timeout")
		}
	}

	if c.conn == nil {
		return nil, fmt.Errorf("icmp: not connected")
	}
	buf := make([]byte, 1500)
	n, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("icmp recv: %w", err)
	}
	msg, err := icmp.ParseMessage(1, buf[:n])
	if err != nil {
		return nil, fmt.Errorf("icmp parse: %w", err)
	}
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		return body.Data, nil
	default:
		return buf[:n], nil
	}
}

func (c *icmpChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (l *icmpListener) Listen(addr string) error {
	conn, err := icmp.ListenPacket("ip4:icmp", addr)
	if err != nil {
		return fmt.Errorf("icmp listener: %w", err)
	}
	l.conn = conn
	return nil
}

func (l *icmpListener) Accept() (Channel, net.Addr, error) {
	if l.conn == nil {
		return nil, nil, fmt.Errorf("icmp listener: not listening")
	}
	buf := make([]byte, 1500)
	n, peer, err := l.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}

	msg, err := icmp.ParseMessage(1, buf[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("icmp parse accept: %w", err)
	}

	var data []byte
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		data = body.Data
	default:
		data = buf[:n]
	}

	ch := &icmpChannel{
		normalizer: traffic.NewNormalizer(traffic.ICMPTraffic),
		id:         uint16(os.Getpid() & 0xFFFF),
		seq:        1,
		isServer:   true,
		listenConn: l.conn,
		clientAddr: peer,
		recvCh:     l.recvCh,
	}

	select {
	case l.recvCh <- data:
	default:
	}

	return ch, peer, nil
}

func (l *icmpListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}
