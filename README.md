# leash

A smart-account wallet for LLM agents where the contract, not the prompt, is the guardrail. The agent holds a session
key; on-chain policy (spend caps, contract + selector allowlist, per-counterparty limits, passkey-approved escalation)
decides what actually executes. An adversarial prompt-injection suite measures how often the agent is fooled versus how
often funds actually leave the account.

## Getting started

Requires Go and [Foundry](https://getfoundry.sh).

```sh
git submodule update --init --recursive && go mod download
go run ./cmd/leash
```

## Development

```sh
make test     # go test -race + forge test
make lint     # go vet, gofmt, forge fmt --check
```
