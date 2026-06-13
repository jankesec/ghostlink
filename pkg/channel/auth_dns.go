package channel

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
)

type AuthDNSServer struct {
	conn      *net.UDPConn
	domain    string
	recvCh    chan []byte
	sendCh    chan []byte
	mu        sync.Mutex
	clients   map[string]*authDNSClient
	running   bool
	processor func([]byte) []byte
}

type authDNSClient struct {
	addr     *net.UDPAddr
	lastSeen int64
	txID     uint16
}

func NewAuthDNSServer(domain string) *AuthDNSServer {
	return &AuthDNSServer{
		domain:  domain,
		recvCh:  make(chan []byte, 256),
		sendCh:  make(chan []byte, 256),
		clients: make(map[string]*authDNSClient),
	}
}

func (s *AuthDNSServer) SetProcessor(fn func([]byte) []byte) {
	s.processor = fn
}

func (s *AuthDNSServer) Listen(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("auth dns resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("auth dns listen: %w", err)
	}
	s.conn = conn
	s.running = true

	go s.serve()
	return nil
}

func (s *AuthDNSServer) serve() {
	buf := make([]byte, 1500)
	for s.running {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if !s.running {
				return
			}
			continue
		}
		s.handleQuery(addr, buf[:n])
	}
}

func (s *AuthDNSServer) handleQuery(addr *net.UDPAddr, raw []byte) {
	if len(raw) < 12 {
		return
	}

	txID := binary.BigEndian.Uint16(raw[0:2])
	flags := binary.BigEndian.Uint16(raw[2:4])
	qdCount := binary.BigEndian.Uint16(raw[4:6])

	if flags&0x8000 != 0 {
		return
	}
	if qdCount == 0 {
		return
	}

	qname, qtype, _, err := parseDNSQuestion(raw, 12)
	if err != nil || qname == "" {
		return
	}

	if !strings.HasSuffix(strings.ToLower(qname), strings.ToLower(s.domain)) {
		s.sendNXDomain(addr, txID)
		return
	}

	clientKey := addr.String()
	s.mu.Lock()
	if _, ok := s.clients[clientKey]; !ok {
		s.clients[clientKey] = &authDNSClient{addr: addr, txID: txID}
	}
	s.mu.Unlock()

	encoded := strings.TrimSuffix(qname, "."+s.domain)
	encoded = strings.TrimSuffix(encoded, ".")
	encoded = strings.ReplaceAll(encoded, ".", "")

	if encoded == "" || encoded == s.domain {
		s.sendEmptyTXT(addr, txID, qname)
		return
	}

	var data []byte
	if encoded != "poll" {
		var err error
		data, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(data) == 0 {
			s.sendEmptyTXT(addr, txID, qname)
			return
		}
	}

	if len(data) > 0 {
		select {
		case s.recvCh <- data:
		default:
		}
	}

	var respData []byte
	select {
	case respData = <-s.sendCh:
	default:
	}

	if respData == nil && s.processor != nil && len(data) > 0 {
		s.processor(data)
	}

	if respData != nil {
		switch qtype {
		case 16:
			s.sendTXTResponse(addr, txID, qname, respData)
		case 5:
			s.sendCNAMEResponse(addr, txID, qname, respData)
		case 15:
			s.sendMXResponse(addr, txID, qname, respData)
		case 1, 28:
			s.sendAResponse(addr, txID, qname, respData, qtype)
		default:
			s.sendTXTResponse(addr, txID, qname, respData)
		}
	} else {
		s.sendEmptyTXT(addr, txID, qname)
	}
}

func (s *AuthDNSServer) SendResponse(data []byte) {
	select {
	case s.sendCh <- data:
	default:
	}
}

func (s *AuthDNSServer) RecvData() <-chan []byte {
	return s.recvCh
}

func (s *AuthDNSServer) Close() error {
	s.running = false
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *AuthDNSServer) sendEmptyTXT(addr *net.UDPAddr, txID uint16, qname string) {
	resp := buildDNSHeader(txID, 0x8180, 0, 0, 0, 0)
	resp = append(resp, buildDNSQuestion(qname, 16, 1)...)
	s.conn.WriteToUDP(resp, addr)
}

func (s *AuthDNSServer) sendNXDomain(addr *net.UDPAddr, txID uint16) {
	resp := buildDNSHeader(txID, 0x8183, 0, 0, 0, 0)
	s.conn.WriteToUDP(resp, addr)
}

func (s *AuthDNSServer) sendTXTResponse(addr *net.UDPAddr, txID uint16, qname string, data []byte) {
	resp := buildDNSHeader(txID, 0x8180, 0, 1, 0, 0)
	resp = append(resp, buildDNSQuestion(qname, 16, 1)...)

	encoded := base64.RawURLEncoding.EncodeToString(data)
	txtLen := len(encoded) + 1

	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x10)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, byte(txtLen>>8), byte(txtLen&0xFF))
	resp = append(resp, byte(len(encoded)))
	resp = append(resp, []byte(encoded)...)

	s.conn.WriteToUDP(resp, addr)
}

func (s *AuthDNSServer) sendCNAMEResponse(addr *net.UDPAddr, txID uint16, qname string, data []byte) {
	resp := buildDNSHeader(txID, 0x8180, 0, 1, 0, 0)
	resp = append(resp, buildDNSQuestion(qname, 5, 1)...)

	encoded := base64.RawURLEncoding.EncodeToString(data)
	cname := encoded + ".c." + s.domain

	var cnameWire []byte
	for _, label := range strings.Split(cname, ".") {
		if label == "" {
			continue
		}
		cnameWire = append(cnameWire, byte(len(label)))
		cnameWire = append(cnameWire, []byte(label)...)
	}
	cnameWire = append(cnameWire, 0x00)

	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x05)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, byte(len(cnameWire)>>8), byte(len(cnameWire)&0xFF))
	resp = append(resp, cnameWire...)

	s.conn.WriteToUDP(resp, addr)
}

func (s *AuthDNSServer) sendMXResponse(addr *net.UDPAddr, txID uint16, qname string, data []byte) {
	resp := buildDNSHeader(txID, 0x8180, 0, 1, 0, 0)
	resp = append(resp, buildDNSQuestion(qname, 15, 1)...)

	encoded := base64.RawURLEncoding.EncodeToString(data)
	mxHost := encoded + ".mx." + s.domain

	var mxWire []byte
	mxWire = append(mxWire, 0x00, 0x0A)
	for _, label := range strings.Split(mxHost, ".") {
		if label == "" {
			continue
		}
		mxWire = append(mxWire, byte(len(label)))
		mxWire = append(mxWire, []byte(label)...)
	}
	mxWire = append(mxWire, 0x00)

	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, 0x00, 0x0F)
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, byte(len(mxWire)>>8), byte(len(mxWire)&0xFF))
	resp = append(resp, mxWire...)

	s.conn.WriteToUDP(resp, addr)
}

func (s *AuthDNSServer) sendAResponse(addr *net.UDPAddr, txID uint16, qname string, data []byte, qtype uint16) {
	resp := buildDNSHeader(txID, 0x8180, 0, 1, 0, 0)
	resp = append(resp, buildDNSQuestion(qname, qtype, 1)...)

	rdata := make([]byte, 4)
	if len(data) >= 4 {
		copy(rdata, data[:4])
	} else {
		copy(rdata, data)
	}

	if qtype == 28 {
		rdata = make([]byte, 16)
		if len(data) >= 16 {
			copy(rdata, data[:16])
		} else {
			copy(rdata, data)
		}
	}

	resp = append(resp, 0xC0, 0x0C)
	resp = append(resp, byte(qtype>>8), byte(qtype&0xFF))
	resp = append(resp, 0x00, 0x01)
	resp = append(resp, 0x00, 0x00, 0x00, 0x3C)
	resp = append(resp, byte(len(rdata)>>8), byte(len(rdata)&0xFF))
	resp = append(resp, rdata...)

	s.conn.WriteToUDP(resp, addr)
}

func parseDNSQuestion(raw []byte, offset int) (qname string, qtype uint16, qclass uint16, err error) {
	if offset >= len(raw) {
		return "", 0, 0, fmt.Errorf("offset beyond packet")
	}

	var labels []string
	pos := offset
	for pos < len(raw) {
		labelLen := int(raw[pos])
		if labelLen == 0 {
			pos++
			break
		}
		if labelLen&0xC0 == 0xC0 {
			if pos+1 >= len(raw) {
				return "", 0, 0, fmt.Errorf("truncated pointer")
			}
			ptr := int(binary.BigEndian.Uint16(raw[pos:pos+2]) & 0x3FFF)
			rest, _, _, _ := parseDNSQuestion(raw, ptr)
			labels = append(labels, rest)
			pos += 2
			break
		}
		pos++
		if pos+labelLen > len(raw) {
			return "", 0, 0, fmt.Errorf("truncated label")
		}
		labels = append(labels, string(raw[pos:pos+labelLen]))
		pos += labelLen
	}

	qname = strings.Join(labels, ".")
	if pos+4 > len(raw) {
		return qname, 0, 0, fmt.Errorf("truncated question")
	}
	qtype = binary.BigEndian.Uint16(raw[pos : pos+2])
	qclass = binary.BigEndian.Uint16(raw[pos+2 : pos+4])
	return qname, qtype, qclass, nil
}

func buildDNSHeader(txID, flags uint16, qd, an, ns, ar uint16) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], txID)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], qd)
	binary.BigEndian.PutUint16(hdr[6:8], an)
	binary.BigEndian.PutUint16(hdr[8:10], ns)
	binary.BigEndian.PutUint16(hdr[10:12], ar)
	return hdr
}

func buildDNSQuestion(qname string, qtype, qclass uint16) []byte {
	var q []byte
	for _, label := range strings.Split(qname, ".") {
		if label == "" {
			continue
		}
		q = append(q, byte(len(label)))
		q = append(q, []byte(label)...)
	}
	q = append(q, 0x00)
	q = append(q, byte(qtype>>8), byte(qtype&0xFF))
	q = append(q, byte(qclass>>8), byte(qclass&0xFF))
	return q
}
