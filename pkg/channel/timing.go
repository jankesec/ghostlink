package channel

import (
	"fmt"
	"math"
	"net"
	"time"

	"github.com/byjanke/ghostlink/pkg/traffic"
)

func init() {
	Register(TimingChannel, func() Channel {
		return &timingChannel{
			normalizer: traffic.NewNormalizer(traffic.IdleTraffic),
			bit0Delay:  50 * time.Millisecond,
			bit1Delay:  150 * time.Millisecond,
			frameGap:   500 * time.Millisecond,
		}
	}, func() Listener {
		return &timingListener{
			recvCh: make(chan []byte, 100),
		}
	})
}

type timingChannel struct {
	conn       *net.UDPConn
	peer       *net.UDPAddr
	normalizer *traffic.Normalizer
	bit0Delay  time.Duration
	bit1Delay  time.Duration
	frameGap   time.Duration

	isServer   bool
	listenConn *net.UDPConn
	clientAddr *net.UDPAddr
	recvCh     chan []byte
}

type timingListener struct {
	conn   *net.UDPConn
	recvCh chan []byte
}

func (c *timingChannel) Info() ChannelInfo {
	return ChannelInfo{
		Type:        TimingChannel,
		Name:        "Inter-Packet Timing",
		Description: "Encodes data in inter-packet delays — bit0=50ms, bit1=150ms. Ultra-stealthy but slow (~40 bps)",
		Capability:  0.95,
	}
}

func (c *timingChannel) Connect(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("timing resolve: %w", err)
	}
	c.peer = udpAddr
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("timing dial: %w", err)
	}
	c.conn = conn
	return nil
}

func (c *timingChannel) Send(data []byte) error {
	bits := bytesToBits(data)

	for i, bit := range bits {
		var delay time.Duration
		if !bit {
			delay = c.bit0Delay
		} else {
			delay = c.bit1Delay
		}

		time.Sleep(delay)

		pkt := []byte{0xAA}
		if i == len(bits)-1 {
			pkt = []byte{0xFF}
		}

		if err := c.sendPkt(pkt); err != nil {
			return err
		}
	}

	time.Sleep(c.frameGap)
	return nil
}

func (c *timingChannel) sendPkt(data []byte) error {
	if c.isServer {
		if c.listenConn == nil || c.clientAddr == nil {
			return fmt.Errorf("timing server: not connected")
		}
		_, err := c.listenConn.WriteToUDP(data, c.clientAddr)
		return err
	}
	_, err := c.conn.Write(data)
	return err
}

func (c *timingChannel) Recv() ([]byte, error) {
	if c.isServer {
		select {
		case data := <-c.recvCh:
			return data, nil
		case <-time.After(60 * time.Second):
			return nil, fmt.Errorf("timing server: recv timeout")
		}
	}

	buf := make([]byte, 1)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *timingChannel) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (l *timingListener) Listen(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("timing listen resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("timing listen: %w", err)
	}
	l.conn = conn
	return nil
}

func (l *timingListener) Accept() (Channel, net.Addr, error) {
	buf := make([]byte, 1)
	n, addr, err := l.conn.ReadFromUDP(buf)
	if err != nil {
		return nil, nil, err
	}

	bits, err := l.readBits(addr, buf[:n])
	if err != nil {
		return nil, nil, err
	}

	data := bitsToBytes(bits)

	select {
	case l.recvCh <- data:
	default:
	}

	ch := &timingChannel{
		normalizer: traffic.NewNormalizer(traffic.IdleTraffic),
		bit0Delay:  50 * time.Millisecond,
		bit1Delay:  150 * time.Millisecond,
		frameGap:   500 * time.Millisecond,
		isServer:   true,
		listenConn: l.conn,
		clientAddr: addr,
		recvCh:     l.recvCh,
	}

	return ch, addr, nil
}

func (l *timingListener) readBits(addr *net.UDPAddr, firstByte []byte) ([]bool, error) {
	var bits []bool
	lastTime := time.Now()

	for {
		buf := make([]byte, 1)
		l.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, remoteAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if remoteAddr.String() != addr.String() {
			continue
		}

		elapsed := time.Since(lastTime)
		lastTime = time.Now()

		midpoint := (l.getBit0Delay() + l.getBit1Delay()) / 2
		bit := elapsed > midpoint

		bits = append(bits, bit)

		if n > 0 && buf[0] == 0xFF {
			break
		}
	}

	if len(bits) == 0 {
		return []bool{}, fmt.Errorf("no bits received")
	}

	return bits, nil
}

func (l *timingListener) getBit0Delay() time.Duration { return 50 * time.Millisecond }
func (l *timingListener) getBit1Delay() time.Duration { return 150 * time.Millisecond }

func (l *timingListener) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func bytesToBits(data []byte) []bool {
	bits := make([]bool, 0, len(data)*8)
	for _, b := range data {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>uint(i))&1 == 1)
		}
	}
	return bits
}

func bitsToBytes(bits []bool) []byte {
	numBytes := int(math.Ceil(float64(len(bits)) / 8))
	data := make([]byte, numBytes)
	for i, bit := range bits {
		if bit {
			data[i/8] |= 1 << uint(7-(i%8))
		}
	}
	return data
}
