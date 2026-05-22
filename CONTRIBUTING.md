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

- **Good First Issues**: Look for issues labeled [`good first issue`](https://github.com/ParleSec/ProtocolSoup/labels/good%20first%20issue) - these are scoped for newcomers
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
| Node.js | 22.13+ | Frontend and docs development |
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

**You must sign off on every commit.** This certifies that you wrote the code or have the right to submit it:

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
4. **Sign commits (DCO)**: Use `git commit -s` so messages include `Signed-off-by`
5. **Open PR**: Submit against `master` with a clear description
6. **Respond to feedback**: Address review comments promptly

### PR Checklist

Before submitting, verify:

- [ ] All commits include `Signed-off-by: Name <email>`
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
| Palette content (`content/**`) | `cd backend && go run ./cmd/content-validate -content ../content && go test ./internal/palette/...` |
| Palette indexer or query service | `cd backend && go test ./internal/palette/... && go run ./cmd/palette-indexer -content ../content -out ./dist/palette.db` |

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

## Palette Content (`content/`)

The homepage search input and global cmd+K palette retrieve from a deterministic in-process index built from the `content/` tree at the repo root. There is no external search service, no embeddings, and no probabilistic ranking. Every result row must carry visible match-reason metadata that points at the structured field that caused it to surface.

### Authoring rules

- **Source of truth is frontmatter** in markdown files under `content/protocols/`, `content/flows/<protocol>/`, `content/concepts/`, and (when produced) `content/spec-assertions/<protocol>/`.
- **Schema**: see [`content/SCHEMA.md`](content/SCHEMA.md) for the full frontmatter contract (required, recommended, and optional fields). That document is canonical; do not duplicate the rules elsewhere.
- **Controlled vocabulary**: only values declared in [`content/taxonomy.yaml`](content/taxonomy.yaml) are valid for the `use_cases`, `actors`, `patterns`, and `problem_domains` axes. New values require a taxonomy PR with a one-line semantic note.
- **Synonyms**: add user-language synonyms to [`content/aliases.yaml`](content/aliases.yaml). Ambiguous aliases keep all mappings; the palette surfaces refinement chips when intent is genuinely ambiguous.
- **Edges**: list `related_concepts` (and, where appropriate, `prerequisite_of` / `governs`) to enable one-hop traversals during retrieval.

### Validator

Every PR that touches `content/` or `backend/internal/palette/` must pass:

```bash
cd backend
go run ./cmd/content-validate -content ../content
go test ./internal/palette/...
```

The validator fails on unknown axis values, missing required fields, duplicate alias keys, dangling edge references, filename/id mismatches, and unknown top-level fields. CI enforces the same set; see `.github/workflows/palette-content.yml`.

### Indexer

A deploy-time Go binary builds the runtime SQLite file:

```bash
cd backend
go run ./cmd/palette-indexer -content ../content -out ./dist/palette.db
```

The build is idempotent — same input produces byte-identical output. Backed by SQLite FTS5 plus structured tables (`artefacts`, `axis_values`, `edges`, `aliases`).

**Canonical paths:** local and CI builds write `backend/dist/palette.db`. Production Docker images (`docker/Dockerfile.backend`, `docker/Dockerfile.fly`) run the indexer at image build time and copy the file to `/app/palette.db`, exposed via `SHOWCASE_PALETTE_DB=/app/palette.db`. Content changes require a backend image rebuild (or a mounted volume at that path for self-hosted monoliths).

### Query service

Mounted at `POST /api/palette/query`. Implementation lives in `backend/internal/palette/`. The pipeline is parse → candidates → rank → match-reason emission → refinement chips. P99 latency budget is 20ms in-process. Tunable weights live in `rank.go`.

Production requires `SHOWCASE_PALETTE_DB` pointing at a readable index file; the server refuses to start in `SHOWCASE_ENV=production` if the path is missing or unreadable. Docker images built from `docker/Dockerfile.backend` and `docker/Dockerfile.fly` bake `/app/palette.db` and set the variable automatically. Verify with `GET /health` (`palette.loaded`) or `GET /api` (`endpoints.palette`).

### Frontend surfaces

Two mount points share one component (`frontend/src/components/palette/Palette.tsx`):

| Surface | Where | Notes |
|---------|-------|-------|
| Homepage input | `/` hero | URL persistence via `?q=&scope=&filter=`; shareable searches |
| cmd+K modal | all other routes | `Cmd/Ctrl+K` or `/`; header **Search** chip on non-home pages |

Keyboard (both surfaces unless noted):

- `↑` / `↓` — navigate results
- `Enter` — open result or dispatch runnable flow to Looking Glass
- `Tab` — apply first refinement chip
- `Esc` — close modal (cmd+K) or reset search (homepage)
- `Cmd/Ctrl+K` — focus homepage input on `/`; toggle modal elsewhere

Homepage URL shape (invalid values are ignored):

```
/?q=pkce&scope=concept&filter=use_cases:mobile_app
```

Recent searches (last 5) persist in `localStorage` under `protocolsoup.palette.recent.v1` and appear in the empty state.

## Project Architecture

Understanding the codebase helps you contribute effectively:

```
ProtocolSoup/
├── backend/
│   ├── cmd/
│   │   ├── server/              # Application entry point
│   │   ├── content-validate/    # Palette content frontmatter validator
│   │   └── palette-indexer/     # Builds the SQLite palette index
│   └── internal/
│       ├── core/                # HTTP server, config, middleware
│       ├── crypto/              # JWT/JWK key management
│       ├── lookingglass/        # Real-time protocol inspection
│       ├── mockidp/             # Mock identity provider
│       ├── palette/             # Indexer + query service for the search palette
│       ├── plugin/              # Plugin system interfaces
│       └── protocols/           # Protocol implementations
├── content/                     # Source of truth for palette artefacts
│   ├── taxonomy.yaml            # Controlled axis vocabulary
│   ├── aliases.yaml             # Synonym map
│   ├── SCHEMA.md                # Frontmatter contract (canonical)
│   ├── protocols/               # Protocol artefacts
│   ├── flows/<protocol>/        # Flow artefacts
│   └── concepts/                # Concept artefacts
├── frontend/
│   └── src/
│       ├── components/
│       │   └── palette/         # Shared retrieval surface (homepage + cmd+K)
│       ├── lookingglass/        # Flow executors & visualization
│       ├── pages/               # Route pages
│       └── protocols/           # Protocol registry
└── docker/                      # Container configurations
```

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed system design documentation.

## Getting Help

- **Bugs/Questions**: Use [GitHub Issues](https://github.com/ParleSec/ProtocolSoup/issues), [GitHub Discussions](https://github.com/ParleSec/ProtocolSoup/discussions), or [SUPPORT.md](SUPPORT.md)
- **Contributor docs**: See [docs.protocolsoup.com/developers/overview](https://docs.protocolsoup.com/developers/overview/)
- **Security issues**: See [SECURITY.md](SECURITY.md) for responsible disclosure

---

Thank you for contributing to ProtocolSoup! Your work helps practitioners understand and implement identity protocols correctly.