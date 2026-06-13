package channel

import (
	"fmt"
	"net"
	"time"

	"github.com/byjanke/ghostlink/pkg/traffic"
)

func init() {
	Register(PacketSizeChannel, func() Channel {
		return &packetSizeChannel{
			normalizer: traffic.NewNormalizer(traffic.IdleTraffic),
		}
	}, func() Listener {
		return &packetSizeListener{
			recvCh: make(chan []byte, 100),
		}
	})
}

const (
	sizeMin      = 64
	sizeMax      = 512
	sizeStep     = 32
	sizeEncBits  = 3
	sizeFrameEnd = 0xFF
)

var sizeSymbols = generateSizeSymbols()

func generateSizeSymbols() []int {
	var sizes []int
	for s := sizeMin + sizeStep; s <= sizeMax; s += sizeStep {
		sizes = append(sizes, s)
	}
	return sizes
}

type packetSizeChannel struct {
	conn       *net.UDPConn
	peer       *net.UDPAddr
	normalizer *traffic.Normalizer

	isServer   bool
	listenConn *net.UDPConn
	clientAddr *net.UDPAddr
	recvCh     chan []byte
}

type packetSizeListener struct {
	conn   *net.UDPConn
	recvCh chan []byte
}

func (c *packetSizeChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        PacketSizeChannel,
		Name:        "Packet Size Modulation",
		Description: "Encodes data in packet payload sizes — 3 bits per packet (8 size ranges). Moderate stealth",
		Capability:  0.80,
	}
}

func (c *packetSizeChannel) Connect(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("pktsize resolve: %w", err)
	}
	c.peer = udpAddr
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("pktsize dial: %w", err)
	}
	c.conn = conn
	return nil
}

func (c *packetSizeChannel) Send(data []byte) error {
	c.normalizer.WaitForSlot()

	for i := 0; i < len(data); i++ {
		high := (data[i] >> 3) & 0x1F
		low := data[i] & 0x07

		for _, nibble := range []byte{high, low} {
			symbolIdx := int(nibble) % len(sizeSymbols)
			payloadSize := sizeSymbols[symbolIdx] - 28

			pkt := make([]byte, payloadSize)
			pkt[0] = 0xBB

			if err := c.sendPkt(pkt); err != nil {
				return err
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	endPkt := make([]byte, sizeMax-28)
	endPkt[0] = sizeFrameEnd
	if err := c.sendPkt(endPkt); err != nil {
		return err
	}

	c.normalizer.RecordSend()
	return nil
}

func (c *packetSizeChannel) sendPkt(data []byte) error {
	if c.isServer {
		if c.listenConn == nil || c.clientAddr == nil {
			return fmt.Errorf("pktsize server: not connected")
		}
		_, err := c.listenConn.WriteToUDP(data, c.clientAddr)
		return err
	}
	_, err := c.conn.Write(data)
	return err
}

func (c *packetSizeChannel) Recv() ([]byte, error) {
	if c.isServer {
		select {
		case data := <-c.recvCh:
			return data, nil
		case <-time.After(30 * time.Second):
			return nil, fmt.Errorf("pktsize server: recv timeout")
		}
	}

	buf := make([]byte, sizeMax)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *packetSizeChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (l *packetSizeListener) Listen(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("pktsize listen resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("pktsize listen: %w", err)
	}
	l.conn = conn
	return nil
}

func (l *packetSizeListener) Accept() (Channel, net.Addr, error) {
	buf := make([]byte, sizeMax)
	n, addr, err := l.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}

	_ = buf[:n]

	var sizes []int
	sizes = append(sizes, n)

	for {
		buf2 := make([]byte, sizeMax)
		l.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n2, remoteAddr, err := l.conn.ReadFromUDP(buf2)
		if err != nil {
			break
		}
		if remoteAddr.String() != addr.String() {
			continue
		}
		sizes = append(sizes, n2)
		if n2 >= sizeMax-28 {
			break
		}
	}

	data := sizesToBytes(sizes)

	select {
	case l.recvCh <- data:
	default:
	}

	ch := &packetSizeChannel{
		normalizer: traffic.NewNormalizer(traffic.IdleTraffic),
		isServer:   true,
		listenConn: l.conn,
		clientAddr: addr,
		recvCh:     l.recvCh,
	}

	return ch, addr, nil
}

func (l *packetSizeListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func sizesToBytes(sizes []int) []byte {
	var data []byte
	var buf byte
	bitCount := 0

	for _, sz := range sizes {
		if sz >= sizeMax-28 {
			break
		}

		closest := sizeMin
		minDiff := 99999
		for _, sym := range sizeSymbols {
			diff := sz - sym
			if diff < 0 {
				diff = -diff
			}
			if diff < minDiff {
				minDiff = diff
				closest = sym
			}
		}

		symbolIdx := 0
		for i, sym := range sizeSymbols {
			if sym == closest {
				symbolIdx = i
				break
			}
		}

		for j := 4; j >= 0; j-- {
			buf = (buf << 1) | byte((symbolIdx>>uint(j))&1)
			bitCount++
			if bitCount == 8 {
				data = append(data, buf)
				buf = 0
				bitCount = 0
			}
		}
	}

	if bitCount > 0 {
		buf <<= uint(8 - bitCount)
		data = append(data, buf)
	}

	return data
}
