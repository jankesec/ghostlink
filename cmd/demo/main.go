package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/byjanke/ghostlink/internal/buildinfo"
	"github.com/byjanke/ghostlink/pkg/channel"
	cryptopkg "github.com/byjanke/ghostlink/pkg/crypto"
	"github.com/byjanke/ghostlink/pkg/encoder"
	"github.com/byjanke/ghostlink/pkg/protocol"
)

const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiGreen = "\x1b[32m"
	ansiCyan  = "\x1b[36m"
)

type validationCheck struct {
	stage       string
	observation string
}

func paint(enabled bool, code, value string) string {
	if !enabled {
		return value
	}
	return code + value + ansiReset
}

func printBoxLine(out io.Writer, color bool, code, text string) {
	padding := 74 - utf8.RuneCountInString(text)
	if padding < 0 {
		padding = 0
	}
	fmt.Fprintf(out, "│  %s%s  │\n", paint(color, code, text), strings.Repeat(" ", padding))
}

func runDemo(out io.Writer, color bool) error {
	payload := []byte(strings.Repeat("authorized-lab telemetry record\n", 24))
	originalDigest := sha256.Sum256(payload)
	checks := make([]validationCheck, 0, 6)

	senderPrivate, senderPublic, err := cryptopkg.GenerateKeyExchange()
	if err != nil {
		return fmt.Errorf("generate sender key: %w", err)
	}
	receiverPrivate, receiverPublic, err := cryptopkg.GenerateKeyExchange()
	if err != nil {
		return fmt.Errorf("generate receiver key: %w", err)
	}
	senderShared, err := cryptopkg.CompleteKeyExchange(senderPrivate, receiverPublic)
	if err != nil {
		return fmt.Errorf("complete sender exchange: %w", err)
	}
	receiverShared, err := cryptopkg.CompleteKeyExchange(receiverPrivate, senderPublic)
	if err != nil {
		return fmt.Errorf("complete receiver exchange: %w", err)
	}
	senderKey := cryptopkg.DeriveKey(senderShared, "ghostlink-local-demo")
	receiverKey := cryptopkg.DeriveKey(receiverShared, "ghostlink-local-demo")
	if !bytes.Equal(senderKey, receiverKey) {
		return fmt.Errorf("derived session keys do not match")
	}
	checks = append(checks, validationCheck{"Key agreement", "P-256 peers derived the same 32-byte session key"})

	senderSession, err := cryptopkg.NewSession(senderKey)
	if err != nil {
		return fmt.Errorf("create sender session: %w", err)
	}
	receiverSession, err := cryptopkg.NewSession(receiverKey)
	if err != nil {
		return fmt.Errorf("create receiver session: %w", err)
	}

	compressed, err := encoder.Encode(payload)
	if err != nil {
		return fmt.Errorf("compress payload: %w", err)
	}
	checks = append(checks, validationCheck{
		"Compression",
		fmt.Sprintf("zlib reduced %d synthetic bytes to %d bytes", len(payload), len(compressed)),
	})

	dataShards, totalShards := encoder.OptimalFECParams(len(compressed))
	fecBlock, err := encoder.XOREncode(compressed, dataShards, totalShards)
	if err != nil {
		return fmt.Errorf("encode parity layout: %w", err)
	}
	fecBytes := encoder.MarshalFECBlock(fecBlock)
	checks = append(checks, validationCheck{
		"Parity layout",
		fmt.Sprintf("%d data shards and %d XOR parity shards encoded", dataShards, totalShards-dataShards),
	})

	frames, err := encoder.SplitIntoFrames(fecBytes, 48)
	if err != nil {
		return fmt.Errorf("split frames: %w", err)
	}
	receivedFrames := make([]encoder.Frame, 0, len(frames))
	for _, frame := range frames {
		wireMessage, err := protocol.MarshalBinary(protocol.Message{
			Type:     protocol.MsgExfilChunk,
			StreamID: 1,
			Payload:  encoder.MarshalFrame(frame),
		})
		if err != nil {
			return fmt.Errorf("encode protocol message: %w", err)
		}
		ciphertext, err := senderSession.Encrypt(wireMessage)
		if err != nil {
			return fmt.Errorf("encrypt frame: %w", err)
		}
		plaintext, err := receiverSession.Decrypt(ciphertext)
		if err != nil {
			return fmt.Errorf("decrypt frame: %w", err)
		}
		message, err := protocol.Unmarshal(plaintext)
		if err != nil {
			return fmt.Errorf("decode protocol message: %w", err)
		}
		decodedFrame, err := encoder.UnmarshalFrame(message.Payload)
		if err != nil {
			return fmt.Errorf("decode frame: %w", err)
		}
		receivedFrames = append(receivedFrames, decodedFrame)
	}
	checks = append(checks, validationCheck{
		"Framing",
		fmt.Sprintf("protocol v%d carried %d sequenced frames", protocol.ProtocolVersion, len(frames)),
	})
	checks = append(checks, validationCheck{
		"Encryption",
		fmt.Sprintf("AES-256-GCM authenticated all %d frames", len(frames)),
	})

	reassembled, err := encoder.ReassembleFrames(receivedFrames)
	if err != nil {
		return fmt.Errorf("reassemble frames: %w", err)
	}
	shards, decodedDataShards, decodedTotalShards, _, err := encoder.UnmarshalFECBlock(reassembled)
	if err != nil {
		return fmt.Errorf("decode parity layout: %w", err)
	}
	recoveredCompressed, err := encoder.FECDecode(
		shards,
		decodedDataShards,
		decodedTotalShards,
		len(compressed),
	)
	if err != nil {
		return fmt.Errorf("recover compressed payload: %w", err)
	}
	recovered, err := encoder.Decode(recoveredCompressed)
	if err != nil {
		return fmt.Errorf("decompress payload: %w", err)
	}
	recoveredDigest := sha256.Sum256(recovered)
	if !bytes.Equal(payload, recovered) || recoveredDigest != originalDigest {
		return fmt.Errorf("end-to-end integrity check failed")
	}
	checks = append(checks, validationCheck{
		"Integrity",
		fmt.Sprintf("SHA-256 %x matched after local round trip", recoveredDigest[:6]),
	})

	fmt.Fprintln(out, "┌──────────────────────────────────────────────────────────────────────────────┐")
	printBoxLine(out, color, ansiBold+ansiCyan, "GHOSTLINK / LOCAL PIPELINE VALIDATION")
	printBoxLine(out, color, "", "Offline · synthetic payload · no sockets · no external services")
	fmt.Fprintln(out, "└──────────────────────────────────────────────────────────────────────────────┘")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%-20s %-9s %s\n", "STAGE", "STATUS", "OBSERVATION")
	fmt.Fprintln(out, strings.Repeat("─", 78))
	for _, check := range checks {
		fmt.Fprintf(out, "%-20s %-9s %s\n", check.stage, paint(color, ansiGreen+ansiBold, "PASS"), check.observation)
	}

	registered := channel.RegisteredChannels()
	transports := make([]string, 0, len(registered))
	for _, transport := range registered {
		transports = append(transports, string(transport))
	}
	sort.Strings(transports)
	fmt.Fprintln(out)
	fmt.Fprintln(out, paint(color, ansiBold, "REGISTERED TRANSPORT INVENTORY"))
	fmt.Fprintln(out, strings.Join(transports, "  ·  "))
	fmt.Fprintln(out, paint(color, ansiDim, "Inventory only; transports are not contacted by this demo."))
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s  %d/%d checks passed\n", paint(color, ansiGreen+ansiBold, "RESULT"), len(checks), len(checks))
	fmt.Fprintln(out, "The local cryptographic and framing pipeline preserved the synthetic payload.")
	fmt.Fprintln(out, paint(color, ansiDim, "Use only in isolated systems you own or are explicitly authorized to test."))
	return nil
}

func main() {
	noColor := flag.Bool("no-color", false, "disable ANSI color output")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}
	info, err := os.Stdout.Stat()
	color := err == nil && info.Mode()&os.ModeCharDevice != 0 && !*noColor && os.Getenv("NO_COLOR") == ""
	if err := runDemo(os.Stdout, color); err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		os.Exit(1)
	}
}
