package channel

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/byjanke/ghostlink/pkg/traffic"
	"golang.org/x/net/ipv4"
)

func init() {
	Register(IPIDChannel, func() Channel {
		return &ipIDChannel{
			normalizer: traffic.NewNormalizer(traffic.TCPTraffic),
		}
	}, func() Listener {
		return &ipIDListener{
			recvCh: make(chan []byte, 100),
		}
	})
}

type ipIDChannel struct {
	conn       *ipv4.RawConn
	dst        net.IP
	normalizer *traffic.Normalizer

	isServer   bool
	listenConn *ipv4.RawConn
	clientAddr net.Addr
	recvCh     chan []byte
}

type ipIDListener struct {
	conn   *ipv4.RawConn
	recvCh chan []byte
}

func (c *ipIDChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        IPIDChannel,
		Name:        "IP ID Modulation",
		Description: "Embeds 2 bytes of data in the IP Identification field of IPv4 packets (requires root)",
		Capability:  0.72,
	}
}

func (c *ipIDChannel) Connect(addr string) error {
	ipAddr, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		return fmt.Errorf("ip_id resolve: %w", err)
	}
	c.dst = ipAddr.IP
	pc, err := net.ListenPacket("ip4:255", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("ip_id raw socket (need root): %w", err)
	}
	conn, err := ipv4.NewRawConn(pc)
	if err != nil {
		pc.Close()
		return fmt.Errorf("ip_id raw conn: %w", err)
	}
	c.conn = conn
	return nil
}

func (c *ipIDChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()

	var id uint16
	if len(data) >= 2 {
		id = binary.BigEndian.Uint16(data[:2])
	} else if len(data) == 1 {
		id = uint16(data[0]) << 8
	} else {
		id = uint16(rand.Intn(0xFFFF))
	}

	iphdr := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20,
		ID:       int(id),
		Flags:    0,
		TTL:      64,
		Protocol: 255,
		Src:      net.IPv4zero,
		Dst:      c.dst,
	}

	payload := make([]byte, 0)
	if err := c.conn.WriteTo(iphdr, payload, nil); err != nil {
		return fmt.Errorf("ip_id write: %w", err)
	}
	c.normalizer.RecordSend()
	return nil
}

func (c *ipIDChannel) Recv() ([]byte, error) {
	if c.isServer {
		select {
		case data := <-c.recvCh:
			return data, nil
		case <-time.After(30 * time.Second):
			return nil, fmt.Errorf("ip_id server: recv timeout")
		}
	}

	buf := make([]byte, 1500)
	hdr, _, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("ip_id recv: %w", err)
	}
	id := uint16(hdr.ID)
	return []byte{byte(id >> 8), byte(id & 0xFF)}, nil
}

func (c *ipIDChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (l *ipIDListener) Listen(addr string) error {
	pc, err := net.ListenPacket("ip4:255", addr)
	if err != nil {
		return fmt.Errorf("ip_id listener raw socket (need root): %w", err)
	}
	conn, err := ipv4.NewRawConn(pc)
	if err != nil {
		pc.Close()
		return fmt.Errorf("ip_id listener raw conn: %w", err)
	}
	l.conn = conn
	return nil
}

func (l *ipIDListener) Accept() (Channel, net.Addr, error) {
	buf := make([]byte, 1500)
	hdr, _, _, err := l.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}

	id := uint16(hdr.ID)
	data := []byte{byte(id >> 8), byte(id & 0xFF)}

	select {
	case l.recvCh <- data:
	default:
	}

	ch := &ipIDChannel{
		normalizer: traffic.NewNormalizer(traffic.TCPTraffic),
		isServer:   true,
		listenConn: l.conn,
		clientAddr: &net.IPAddr{IP: hdr.Src},
		recvCh:     l.recvCh,
	}

	return ch, &net.IPAddr{IP: hdr.Src}, nil
}

func (l *ipIDListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}
