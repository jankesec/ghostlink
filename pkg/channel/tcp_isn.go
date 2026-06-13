package channel

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/byjanke/ghostlink/pkg/traffic"
	"golang.org/x/net/ipv4"
)

func init() {
	Register(TCPISNChannel, func() Channel {
		return &tcpISNChannel{
			normalizer: traffic.NewNormalizer(traffic.TCPTraffic),
		}
	}, func() Listener {
		return &tcpISNListener{}
	})
}

type tcpISNChannel struct {
	conn       *ipv4.RawConn
	dst        net.IP
	dstPort    int
	normalizer *traffic.Normalizer
	seqBase    uint32
}

type tcpISNListener struct {
	conn *ipv4.RawConn
}

func (c *tcpISNChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        TCPISNChannel,
		Name:        "TCP ISN Modulation",
		Description: "Embeds data in the TCP Initial Sequence Number field of SYN packets (requires root)",
		Capability:  0.70,
	}
}

func (c *tcpISNChannel) Connect(addr string) error {
	ipAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp_isn resolve: %w", err)
	}
	c.dst = ipAddr.IP
	c.dstPort = ipAddr.Port
	pc, err := net.ListenPacket("ip4:6", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("tcp_isn raw socket (need root): %w", err)
	}
	conn, err := ipv4.NewRawConn(pc)
	if err != nil {
		pc.Close()
		return fmt.Errorf("tcp_isn raw conn: %w", err)
	}
	c.conn = conn
	c.seqBase = uint32(time.Now().UnixNano())
	return nil
}

func (c *tcpISNChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()

	var payload uint16
	if len(data) >= 2 {
		payload = binary.BigEndian.Uint16(data[:2])
	} else if len(data) == 1 {
		payload = uint16(data[0]) << 8
	}
	isn := c.seqBase ^ uint32(payload)<<16

	iphdr := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 40,
		ID:       int(time.Now().UnixNano() & 0xFFFF),
		Flags:    0x40,
		TTL:      64,
		Protocol: 6,
		Src:      net.IPv4zero,
		Dst:      c.dst,
	}

	tcpHdr := buildTCPSYNHeaderRaw(isn, c.dstPort)
	packet := append(tcpHdr, make([]byte, 0)...)
	_ = packet

	if err := c.conn.WriteTo(iphdr, tcpHdr, nil); err != nil {
		return fmt.Errorf("tcp_isn write: %w", err)
	}
	c.normalizer.RecordSend()
	return nil
}

func (c *tcpISNChannel) Recv() ([]byte, error) {
	buf := make([]byte, 1500)
	hdr, payload, _, err := c.conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("tcp_isn recv: %w", err)
	}
	_ = hdr
	if len(payload) < 20 {
		return nil, fmt.Errorf("packet too short for TCP")
	}
	seq := binary.BigEndian.Uint32(payload[4:8])
	data := uint16((seq ^ c.seqBase) >> 16)
	return []byte{byte(data >> 8), byte(data & 0xFF)}, nil
}

func (c *tcpISNChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (l *tcpISNListener) Listen(addr string) error {
	pc, err := net.ListenPacket("ip4:6", addr)
	if err != nil {
		return fmt.Errorf("tcp_isn listener raw socket (need root): %w", err)
	}
	conn, err := ipv4.NewRawConn(pc)
	if err != nil {
		pc.Close()
		return fmt.Errorf("tcp_isn listener raw conn: %w", err)
	}
	l.conn = conn
	return nil
}

func (l *tcpISNListener) Accept() (Channel, net.Addr, error) {
	buf := make([]byte, 1500)
	_, _, _, err := l.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	ch := &tcpISNChannel{
		normalizer: traffic.NewNormalizer(traffic.TCPTraffic),
	}
	return ch, nil, nil
}

func (l *tcpISNListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func buildTCPSYNHeaderRaw(isn uint32, dstPort int) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], uint16(time.Now().UnixNano()&0xFFFF))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(hdr[4:8], isn)
	hdr[8] = 0x00
	hdr[9] = 0x00
	hdr[10] = 0x00
	hdr[11] = 0x00
	hdr[12] = 0x50
	hdr[13] = 0x02
	hdr[14] = 0xFF
	hdr[15] = 0xFF
	hdr[16] = 0x00
	hdr[17] = 0x00
	hdr[18] = 0x00
	hdr[19] = 0x00
	return hdr
}
