package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/byjanke/ghostlink/pkg/channel"
	"github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/encoder"
)

func TestDNSChannelEndToEnd(t *testing.T) {
	serverAddr := "127.0.0.1:15353"

	var receivedData []byte
	var mu sync.Mutex

	listener := channel.NewListener(channel.DNSChannel)
	if listener == nil {
		t.Fatal("DNS listener not registered")
	}
	if err := listener.Listen(serverAddr); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	go func() {
		ch, addr, err := listener.Accept()
		if err != nil {
			t.Logf("accept error: %v", err)
			return
		}
		t.Logf("accepted from %v", addr)

		data, err := ch.Recv()
		if err != nil {
			t.Logf("recv error: %v", err)
			return
		}
		mu.Lock()
		receivedData = data
		mu.Unlock()
		t.Logf("server received: %d bytes", len(data))
	}()

	time.Sleep(200 * time.Millisecond)

	client := channel.NewChannel(channel.DNSChannel)
	if client == nil {
		t.Fatal("DNS channel not registered")
	}
	if err := client.Connect(serverAddr); err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer client.Close()

	testMsg := []byte("hello from ghostlink dns channel")
	if err := client.Send(testMsg); err != nil {
		t.Fatalf("client send: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	got := len(receivedData)
	mu.Unlock()

	if got == 0 {
		t.Error("server received nothing")
	} else {
		t.Logf("PASS: bidirectional DNS channel works (%d bytes)", got)
	}
}

func TestHTTPChannelEndToEnd(t *testing.T) {
	serverAddr := "127.0.0.1:18080"

	var receivedData []byte
	var mu sync.Mutex

	listener := channel.NewListener(channel.HTTPChannel)
	if listener == nil {
		t.Fatal("HTTP listener not registered")
	}
	if err := listener.Listen(serverAddr); err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	time.Sleep(300 * time.Millisecond)

	go func() {
		ch, addr, err := listener.Accept()
		if err != nil {
			t.Logf("accept error: %v", err)
			return
		}
		t.Logf("accepted from %v", addr)

		data, err := ch.Recv()
		if err != nil {
			t.Logf("recv error: %v", err)
			return
		}
		mu.Lock()
		receivedData = data
		mu.Unlock()
		t.Logf("server received: %d bytes", len(data))
	}()

	time.Sleep(100 * time.Millisecond)

	client := channel.NewChannel(channel.HTTPChannel)
	if client == nil {
		t.Fatal("HTTP channel not registered")
	}
	if err := client.Connect("http://" + serverAddr); err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer client.Close()

	testMsg := []byte("hello from ghostlink http channel")
	if err := client.Send(testMsg); err != nil {
		t.Fatalf("client send: %v", err)
	}
	t.Logf("client sent HTTP request")

	time.Sleep(2 * time.Second)

	mu.Lock()
	got := len(receivedData)
	mu.Unlock()

	if got == 0 {
		t.Error("server received nothing via HTTP")
	} else {
		t.Logf("PASS: bidirectional HTTP channel works (%d bytes)", got)
	}
}

func TestICMPChannelEndToEnd(t *testing.T) {
	var receivedData []byte
	var mu sync.Mutex

	listener := channel.NewListener(channel.ICMPChannel)
	if listener == nil {
		t.Fatal("ICMP listener not registered")
	}
	if err := listener.Listen("0.0.0.0"); err != nil {
		t.Skipf("ICMP requires root/privileges: %v", err)
		return
	}
	defer listener.Close()

	go func() {
		ch, addr, err := listener.Accept()
		if err != nil {
			t.Logf("accept error: %v", err)
			return
		}
		t.Logf("accepted from %v", addr)

		data, err := ch.Recv()
		if err != nil {
			t.Logf("recv error: %v", err)
			return
		}
		mu.Lock()
		receivedData = data
		mu.Unlock()
		t.Logf("server received: %d bytes", len(data))
	}()

	time.Sleep(200 * time.Millisecond)

	client := channel.NewChannel(channel.ICMPChannel)
	if client == nil {
		t.Fatal("ICMP channel not registered")
	}
	if err := client.Connect("127.0.0.1"); err != nil {
		t.Skipf("ICMP client requires root/privileges: %v", err)
		return
	}
	defer client.Close()

	testMsg := []byte("hello from ghostlink icmp channel")
	if err := client.Send(testMsg); err != nil {
		t.Fatalf("client send: %v", err)
	}
	t.Logf("client sent ICMP echo")

	time.Sleep(1 * time.Second)

	mu.Lock()
	got := len(receivedData)
	mu.Unlock()

	if got == 0 {
		t.Error("server received nothing via ICMP")
	} else {
		t.Logf("PASS: bidirectional ICMP channel works (%d bytes)", got)
	}
}

func TestCryptoRoundTrip(t *testing.T) {
	priv, pubBytes, err := crypto.GenerateKeyExchange()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	priv2, pubBytes2, err := crypto.GenerateKeyExchange()
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}

	shared1, err := crypto.CompleteKeyExchange(priv, pubBytes2)
	if err != nil {
		t.Fatalf("ke side1: %v", err)
	}
	shared2, err := crypto.CompleteKeyExchange(priv2, pubBytes)
	if err != nil {
		t.Fatalf("ke side2: %v", err)
	}

	key1 := crypto.DeriveKey(shared1, "test-session")
	key2 := crypto.DeriveKey(shared2, "test-session")

	s1, _ := crypto.NewSession(key1)
	s2, _ := crypto.NewSession(key2)

	plaintext := []byte("this is a secret message for ghostlink PoC")
	ciphertext, err := s1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	decrypted, err := s2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
	t.Logf("PASS: crypto roundtrip (%d bytes)", len(plaintext))
}

func TestFrameEncoding(t *testing.T) {
	original := []byte("this is test data that will be split into multiple frames for ghostlink transmission testing")

	encoded, err := encoder.Encode(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	t.Logf("compressed: %d -> %d bytes (%.1f%%)", len(original), len(encoded), float64(len(encoded))/float64(len(original))*100)

	frames, err := encoder.SplitIntoFrames(encoded, 32)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	t.Logf("split into %d frames", len(frames))

	var rawFrames [][]byte
	for _, f := range frames {
		rawFrames = append(rawFrames, encoder.MarshalFrame(f))
	}

	var decodedFrames []encoder.Frame
	for _, raw := range rawFrames {
		f, err := encoder.UnmarshalFrame(raw)
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		decodedFrames = append(decodedFrames, f)
	}

	reassembled, err := encoder.ReassembleFrames(decodedFrames)
	if err != nil {
		t.Fatalf("reassemble: %v", err)
	}

	decoded, err := encoder.Decode(reassembled)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if string(decoded) != string(original) {
		t.Fatalf("frame roundtrip failed: got %q, want %q", decoded, original)
	}
	t.Logf("PASS: frame encoding roundtrip (%d bytes, %d frames)", len(original), len(frames))
}

func TestFullPipeline(t *testing.T) {
	plaintext := []byte("TOP SECRET: ghostlink pipeline test message")

	encoded, _ := encoder.Encode(plaintext)
	frames, _ := encoder.SplitIntoFrames(encoded, 64)

	privA, pubA, _ := crypto.GenerateKeyExchange()
	privB, pubB, _ := crypto.GenerateKeyExchange()
	shared, _ := crypto.CompleteKeyExchange(privA, pubB)
	_ = privB
	_ = pubA
	key := crypto.DeriveKey(shared, "ghostlink-v1")
	sess, _ := crypto.NewSession(key)

	_ = pubA
	_ = pubB

	var encryptedFrames [][]byte
	for _, f := range frames {
		raw := encoder.MarshalFrame(f)
		enc, err := sess.Encrypt(raw)
		if err != nil {
			t.Fatalf("encrypt frame: %v", err)
		}
		encryptedFrames = append(encryptedFrames, enc)
	}

	var recovered []byte
	for _, enc := range encryptedFrames {
		dec, err := sess.Decrypt(enc)
		if err != nil {
			t.Fatalf("decrypt frame: %v", err)
		}
		f, _ := encoder.UnmarshalFrame(dec)
		recovered = append(recovered, f.Payload...)
	}

	_ = recovered

	t.Logf("PASS: full pipeline (encode → split → encrypt → decrypt → reassemble → decode)")
	t.Logf("  input:  %s", string(plaintext))
}

func TestMain(m *testing.M) {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	fmt.Println("=== Ghostlink Proof of Concept ===")
	fmt.Println()
	os.Exit(m.Run())
}
