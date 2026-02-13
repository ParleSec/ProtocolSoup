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
- [ ] Tested locally with `go run ./cmd/server` and `npm run dev`
- [ ] Other (describe below)

## Checklist

<!-- Complete all items before requesting review. -->

- [ ] My commits are signed off (`git commit -s`) per the [DCO](https://developercertificate.org/)
- [ ] I have read the [CONTRIBUTING](https://github.com/ParleSec/ProtocolSoup/blob/master/CONTRIBUTING.md) guide
- [ ] Backend compiles: `cd backend && go build ./...`
- [ ] Backend passes lint: `cd backend && golangci-lint run ./...`
- [ ] Frontend passes lint: `cd frontend && npm run lint`
- [ ] Frontend type-checks: `cd frontend && npx tsc --noEmit`
- [ ] I have updated documentation if needed
- [ ] I have not committed secrets, credentials, or `.env` files

## Screenshots / Looking Glass output

<!-- If this is a UI change or protocol change, include screenshots or Looking Glass timeline output. -->
