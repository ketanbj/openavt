# AVA CLI walkthrough

[Authority and trust boundaries](authority.md) · [Quickstart](quickstart.md)

For a disposable end-to-end call, use `openavt delegation-demo`. These commands
create a **persistent local service**. Run them in a checkout after installing:

```sh
uv sync --locked --extra authority
source .venv/bin/activate
```

Use new output paths: commands refuse to overwrite bundles, keys or credentials.

## 1. Start the authority and business

```sh
openavt ava init --state output/ava
openavt ava business-init --state output/business --ava-state output/ava
openavt ava customer --state output/business --ava-state output/ava \
  --customer alice --resource demo-order-1234 \
  --credentials output/alice.credentials.json
openavt ava serve --state output/ava --business-state output/business \
  --host 127.0.0.1 --port 8400
```

Customer provisioning is an operator action. Public account enrollment cannot
create customer permissions. HTTP is allowed on loopback; off-loopback binding
requires `--https-cert` and `--https-key`. Remote hosting has not been verified.

## 2. Enroll an agent

Activate the environment in another terminal. Obtain `root.pem` from the operator
over a trusted channel, then run:

```sh
openavt ava account --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json
openavt ava enroll --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json --agent assistant \
  --root output/ava/root.pem --output output/enrolled-agent
```

The private key stays on the client. Credential and grant files are mode 0600;
the client never trusts a downloaded root automatically and refuses redirects.

## 3. Grant customer consent

```sh
openavt ava consent --url http://127.0.0.1:8400 \
  --credentials output/alice.credentials.json \
  --agent-cert output/enrolled-agent/agent.pem \
  --action order.read --resource demo-order-1234 --ttl 300 \
  --output output/alice.grant.json
```

The command prints metadata and stores the token in the protected grant file.
Present it with a fresh business challenge over audio TLS; see
[backend integration](authority.md#backend-integration).

## 4. Renew or revoke

Renew into a new bundle; the CLI can reuse the existing private key:

```sh
openavt ava renew --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json --agent assistant \
  --root output/ava/root.pem --key output/enrolled-agent/agent.key \
  --output output/renewed-agent
```

Renewal needs fresh consent because grants bind to the exact certificate, even
when the key is reused. Schedule renewal externally; no daemon is included.

Use the printed grant ID or certificate serial to revoke:

```sh
openavt ava withdraw-consent --url http://127.0.0.1:8400 \
  --credentials output/alice.credentials.json --grant-id GRANT_ID
openavt ava revoke --url http://127.0.0.1:8400 \
  --credentials output/agent.credentials.json --serial CERTIFICATE_SERIAL
```

The operator can also run `openavt ava revoke-grant --state output/business
--ava-state output/ava --grant-id GRANT_ID`. Revocation is checked by the
business backend on each request, rather than by OpenSSL automatically.

## Service behavior

Use `openavt ava COMMAND --help` for options. The API is implemented in
[service.py](../src/openavt/authority/service.py); it is ACME-inspired, not ACME-compatible.

At worker capacity HTTP requests receive 503 or a closed connection; HTTPS
overload closes before its handshake. The client reports transport failure as
`authority_unavailable` (503) without automatic retry. The local service has no
high-availability or distributed DoS guarantee.
