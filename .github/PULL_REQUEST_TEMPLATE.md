## What does this PR do?

<!-- Briefly describe the change and its motivation. Link to the related issue if one exists. -->

Fixes #

## Type of change

<!-- Check the one that applies -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Enhancement (improvement to existing functionality)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] New protocol implementation

## How was this tested?

<!-- Describe how you verified your changes work correctly. -->

- [ ] Ran the affected flow in Looking Glass and verified real-time events
- [ ] Tested locally with `cd backend && go run ./cmd/server` and `cd frontend && npm run dev`
- [ ] Other (describe below)

## Validation checklist

<!-- Run the checks that match your change. Mark not applicable items as N/A in the PR description. -->

- [ ] Backend: `cd backend && go build ./... && go test ./...`
- [ ] Backend lint: `cd backend && golangci-lint run ./...`
- [ ] Frontend: `cd frontend && npm run lint && npx tsc --noEmit && npm run build`
- [ ] Frontend references: `cd frontend && npm run verify-refs`
- [ ] Wallet UI: `cd wallet-ui && npx tsc --noEmit && npm run build`
- [ ] Docs: `cd docs/starlight && npm run build`
- [ ] OpenAPI: `npx @redocly/cli lint --config redocly.yaml gateway@v1 scim@v1 federation@v1 vc@v1`
- [ ] Docker/topology: `cd docker && docker compose config`
- [ ] OID4VCI/OID4VP conformance: `cd backend && go test ./internal/protocols/oid4vci ./internal/protocols/oid4vp -count=1`

## Checklist

<!-- Complete all items before requesting review. -->

- [ ] My commits include DCO sign-off (`git commit -s`) per the [DCO](https://developercertificate.org/), or I've asked for maintainer help to add it before merge
- [ ] I have read the [CONTRIBUTING](https://github.com/ParleSec/ProtocolSoup/blob/master/CONTRIBUTING.md) guide
- [ ] I selected the relevant validation checks above
- [ ] I have updated documentation if needed
- [ ] I have not committed secrets, credentials, or `.env` files

## Screenshots / Looking Glass output

<!-- If this is a UI change or protocol change, include screenshots or Looking Glass timeline output. -->
