package shell

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
)

type Shell struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	mu     sync.Mutex
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
	return cmd.CombinedOutput()
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
		s.cmd.Wait()
	}
	return nil
}
