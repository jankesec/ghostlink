package shell

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
)

const maxCommandOutput = 10 * 1024 * 1024

type Shell struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	mu      sync.Mutex
	running bool
}

func Spawn() (*Shell, error) {
	cmd := exec.Command("/bin/sh", "-i")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start shell: %w", err)
	}

	return &Shell{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		running: true,
	}, nil
}

func ExecCommand(command string) ([]byte, error) {
	cmd := exec.Command("/bin/sh", "-c", command)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitWriter{w: &stdout, max: maxCommandOutput}
	cmd.Stderr = &limitWriter{w: &stderr, max: maxCommandOutput}
	err := cmd.Run()
	output := append(stdout.Bytes(), stderr.Bytes()...)
	if stdout.Len() >= maxCommandOutput || stderr.Len() >= maxCommandOutput {
		output = append(output, []byte("\n[...output truncated]")...)
	}
	return output, err
}

type limitWriter struct {
	w   io.Writer
	n   int64
	max int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n >= l.max {
		return len(p), nil
	}
	remaining := l.max - l.n
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := l.w.Write(p)
	l.n += int64(n)
	return len(p), err
}

func (s *Shell) WriteStdin(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return 0, fmt.Errorf("shell not running")
	}
	return s.stdin.Write(data)
}

func (s *Shell) ReadStdout(buf []byte) (int, error) {
	return s.stdout.Read(buf)
}

func (s *Shell) ReadStderr(buf []byte) (int, error) {
	return s.stderr.Read(buf)
}

func (s *Shell) Resize(rows, cols int) error {
	return nil
}

func (s *Shell) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return nil
	}
	s.running = false
	s.stdin.Close()
	if s.cmd.Process != nil {
		s.cmd.Process.Signal(syscall.SIGTERM)
		if err := s.cmd.Wait(); err != nil {
			_ = err
		}
	}
	return nil
}
