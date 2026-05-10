# Contributing to ProtocolSoup

Thank you for your interest in contributing to ProtocolSoup! This project aims to make identity protocols approachable through hands-on experimentation—and contributions from the community are essential to that mission.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Contributions](#making-contributions)
- [Pull Request Process](#pull-request-process)
- [Local Validation Matrix](#local-validation-matrix)
- [Coding Standards](#coding-standards)
- [Adding New Protocols](#adding-new-protocols)
- [Getting Help](#getting-help)

## Getting Started

### Finding Something to Work On

- **Good First Issues**: Look for issues labeled [`good first issue`](https://github.com/ParleSec/ProtocolSoup/labels/good%20first%20issue)-these are scoped for newcomers
- **Help Wanted**: Issues labeled [`help wanted`](https://github.com/ParleSec/ProtocolSoup/labels/help%20wanted) are ready for contribution
- **Protocol Requests**: Check for new protocol proposals if you have domain expertise

Before starting work on a significant change, please open an issue to discuss your approach. This prevents duplicate effort and ensures alignment with project direction.

### Claiming an Issue

Comment on the issue to let maintainers know you're working on it. If you don't see activity on an issue for two weeks after someone claims it, feel free to pick it up.

## Development Setup

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.25+ | Backend development |
| Node.js | 22.12+ | Frontend and docs development |
| Docker | Latest | Container orchestration |
| Git | Latest | Version control |

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/ParleSec/ProtocolSoup.git
cd ProtocolSoup

# Backend setup
cd backend
go mod download
go build ./...

# Frontend setup
cd ../frontend
npm ci
```

### Running Locally

**Option 1: Split development (recommended for frontend work)**

```bash
# Terminal 1: Start backend monolith
cd ProtocolSoup/backend
go run ./cmd/server

# Terminal 2: Start frontend dev server
cd ProtocolSoup/frontend
npm run dev
```

The frontend runs at `http://localhost:3000` and proxies API requests to the backend at `http://localhost:8080`.

**Option 2: Docker Compose (full stack)**

```bash
cd docker
docker compose up -d
```

**Option 3: With SPIFFE/SPIRE**

```bash
cd docker
docker compose -f docker-compose.yml -f docker-compose.spiffe.yml up -d
```

### Verifying Your Setup

1. Open `http://localhost:3000` (with Docker Compose this includes the frontend; API-only checks can use `http://localhost:8080`)
2. Navigate to Looking Glass
3. Run an OAuth 2.0 Authorization Code flow
4. Verify you see real-time events in the timeline

## Making Contributions

### Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) to ensure contributions can be legally distributed under our Apache 2.0 license.

**Sign off on your commits** (or on the single squashed commit at merge). This certifies that you wrote the code or have the right to submit it:

```bash
git commit -s -m "Add feature X"
```

This adds a `Signed-off-by: Your Name <your.email@example.com>` line to your commit.

**Configure Git to sign off automatically:**

```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

If you forget to sign off, amend your commit:

```bash
git commit --amend -s
```

For multiple commits:

```bash
git rebase HEAD~N --signoff  # where N is the number of commits
```

Check that every commit includes a DCO sign-off before opening a PR:

```bash
git log --format='%h %s%n%b' origin/master..HEAD
```

Each commit message should contain a `Signed-off-by: Name <email>` line. Cryptographic commit signatures are separate from DCO sign-off and are not required.

There is **no automated DCO check** on pull requests: CI does not fail solely for a missing sign-off. Maintainers verify DCO before merge and can walk you through `amend` / `rebase --signoff` if you forgot. Squash-merge often produces a single signed-off commit.

### Branch Naming

Use descriptive branch names:

- `feature/webauthn-support`
- `fix/oauth-pkce-validation`
- `docs/spiffe-setup-guide`

### Commit Messages

Write clear, descriptive commit messages:

```
Add PKCE validation to OAuth 2.0 token endpoint

- Implement code_verifier validation against code_challenge
- Support S256 and plain challenge methods
- Add test coverage for PKCE edge cases

Signed-off-by: Your Name <your.email@example.com>
```

## Pull Request Process

1. **Fork and branch**: Create a feature branch from `master`
2. **Make changes**: Implement your feature or fix
3. **Test locally**: Ensure all tests pass
4. **Sign commits (DCO)**: Use `git commit -s` so messages include `Signed-off-by`; ask in the PR if you need help fixing sign-off
5. **Open PR**: Submit against `master` with a clear description
6. **Respond to feedback**: Address review comments promptly

### PR Checklist

Before submitting, verify:

- [ ] DCO: commits include `Signed-off-by` before merge, or you've noted that you need maintainer help to fix sign-off
- [ ] Relevant commands from the [local validation matrix](#local-validation-matrix) pass
- [ ] Code follows project style guidelines
- [ ] Documentation is updated if needed
- [ ] No secrets or credentials are committed
- [ ] PR description explains the change and motivation

### Review Process

- A maintainer will review your PR within a few days
- CI checks must pass before merge
- At least one maintainer approval is required
- Squash-merge is used for most contributions

## Local Validation Matrix

Run the smallest set that covers your change. CI may run additional checks, but this matrix gives maintainers a reliable starting point for review.

| Change area | Local commands |
|-------------|----------------|
| Backend Go code | `cd backend && go build ./... && go test ./...` |
| Backend lint-sensitive changes | `cd backend && golangci-lint run ./...` |
| Frontend UI or Looking Glass | `cd frontend && npm ci && npm run lint && npx tsc --noEmit && npm run build` |
| Frontend protocol references | `cd frontend && npm run verify-refs` |
| Wallet UI | `cd wallet-ui && npm ci && npx tsc --noEmit && npm run build` |
| Docs site | `cd docs/starlight && npm ci && npm run build` |
| OpenAPI contracts | `npx @redocly/cli lint --config redocly.yaml gateway@v1 scim@v1 federation@v1 vc@v1` |
| Docker or service topology | `cd docker && docker compose config` and, when practical, `docker compose up -d` |
| OID4VCI/OID4VP protocol behavior | `cd backend && go test ./internal/protocols/oid4vci ./internal/protocols/oid4vp -count=1` |

When Snyk or other security scans are skipped for forked PRs because repository secrets are unavailable, maintainers may rerun or review those checks after initial triage.

## Coding Standards

### Go (Backend)

- Follow [Effective Go](https://go.dev/doc/effective_go) conventions
- Run `golangci-lint` before committing
- Use meaningful variable and function names
- Add comments for exported functions and types
- Handle errors explicitly-don't ignore them

```bash
# Install linter
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0

# Run linter
golangci-lint run ./...
```

### TypeScript/React (Frontend)

- Follow the existing ESLint configuration
- Use TypeScript strict mode
- Prefer functional components with hooks
- Use Tailwind CSS for styling (no separate CSS files)
- Keep components focused and composable

```bash
# Run linter
npm run lint

# Type check
npx tsc --noEmit
```

### Testing Requirements

- **Backend**: Add tests for new endpoints and business logic
- **Protocol implementations**: Include tests for happy path and error cases

```bash
# Backend tests
cd backend && go test ./... -v
```

## Adding New Protocols

ProtocolSoup uses a plugin architecture for protocols. See [ADDING_PROTOCOLS.md](docs/ADDING_PROTOCOLS.md) for the complete guide.

### Quick Overview

1. Create plugin directory: `backend/internal/protocols/newprotocol/`
2. Implement the `ProtocolPlugin` interface in `plugin.go`
3. Add HTTP handlers in `handlers.go`
4. Register in `cmd/server/main.go`
5. Create frontend components in `frontend/src/components/protocols/newprotocol/`
6. Add Looking Glass integration for real-time visualization

### Protocol Contribution Guidelines

When proposing a new protocol:

1. **Open an issue first** describing the protocol and its value to practitioners
2. **Reference the RFC(s)** or specifications you're implementing
3. **Start with core flows** before edge cases
4. **Emit Looking Glass events** for all significant operations-visibility is our differentiator

## Project Architecture

Understanding the codebase helps you contribute effectively:

```
ProtocolSoup/
├── backend/
│   ├── cmd/server/          # Application entry point
│   └── internal/
│       ├── core/            # HTTP server, config, middleware
│       ├── crypto/          # JWT/JWK key management
│       ├── lookingglass/    # Real-time protocol inspection
│       ├── mockidp/         # Mock identity provider
│       ├── plugin/          # Plugin system interfaces
│       └── protocols/       # Protocol implementations
├── frontend/
│   └── src/
│       ├── components/      # Shared UI components
│       ├── lookingglass/    # Flow executors & visualization
│       ├── pages/           # Route pages
│       └── protocols/       # Protocol registry
└── docker/                  # Container configurations
```

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed system design documentation.

## Getting Help

- **Bugs/Questions**: Use [GitHub Issues](https://github.com/ParleSec/ProtocolSoup/issues), [GitHub Discussions](https://github.com/ParleSec/ProtocolSoup/discussions), or [SUPPORT.md](SUPPORT.md)
- **Contributor docs**: See [docs.protocolsoup.com/developers/overview](https://docs.protocolsoup.com/developers/overview/)
- **Security issues**: See [SECURITY.md](SECURITY.md) for responsible disclosure

---

Thank you for contributing to ProtocolSoup! Your work helps practitioners understand and implement identity protocols correctly.