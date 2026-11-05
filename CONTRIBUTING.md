# Contributing to Ghostlink

Ghostlink accepts improvements that make authorized lab research safer, more reproducible,
and easier to review.

## Development setup

```bash
git clone https://github.com/jankesec/ghostlink.git
cd ghostlink
make check
make build
go run ./cmd/demo
```

Before opening a pull request, run:

```bash
make fmt
make check
go test -race ./...
```

## Safety and evidence rules

- Use only synthetic data, loopback addresses, or an isolated environment you are
  explicitly authorized to test.
- Never commit credentials, access tokens, customer data, real target addresses, or
  captured third-party traffic.
- Describe what a test proves and what it does not prove. Do not label an implementation
  stealthy, undetectable, production-ready, or loss-tolerant without reproducible evidence.
- Network-facing features must default to loopback unless a broader bind is essential and
  explicitly documented.
- Files that may contain received lab data must use owner-only permissions.
- New transport behavior needs deterministic unit tests and a bounded loopback integration
  test where practical.

## Demo changes

The README demo must execute the real offline validator. Do not replace it with scripted
output, invented hosts, fabricated sessions, or simulated findings.

```bash
make record-demo
```

After recording, inspect a late frame from both the GIF and MP4 and confirm that no secret,
personal path, external hostname, or live network activity appears.

## Pull request checklist

- The change has a narrow, documented purpose.
- `make check`, `make build`, and `go test -race ./...` pass.
- Security-sensitive defaults remain loopback/private.
- Documentation and examples use synthetic data.
- Generated demo assets match `docs/demo.tape`.
