# Contributing to peep

Thanks for your interest in contributing! peep is a small project and every contribution matters — whether it's a bug fix, a new feature, or a docs improvement.

## Prerequisites

- **Go 1.23+**
- **git**

## Getting Started

```bash
git clone https://github.com/thexsa/peep.git
cd peep
make build
make test
```

## Project Structure

| Directory              | Purpose                                  |
| ---------------------- | ---------------------------------------- |
| `cmd/peep/`            | Entry point                              |
| `internal/probe/`      | TLS connection and handshake             |
| `internal/analyzer/`   | Certificate and chain analysis           |
| `internal/education/`  | Built-in documentation content           |
| `internal/ui/`         | Terminal rendering (lipgloss)            |
| `internal/cli/`        | Cobra commands and flag handling          |
| `internal/updater/`    | Self-update logic                        |

## Code Style

- Run `gofmt` and `go vet` before committing. No external linters required.

## Making Changes

1. Fork the repo
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Run `make test` and `go vet ./...`
5. Open a PR with a clear description of what changed and why

## What to Contribute

- Bug fixes
- New protocol support
- Documentation improvements
- New educational topics
- UI improvements

## What to Avoid

- **Don't add external dependencies without discussion first.** Open an issue to propose it.
- **Don't break existing JSON output format** — it's a public API. If you need to change it, propose the change in an issue first.

## Questions?

Open an issue. We're happy to help.
