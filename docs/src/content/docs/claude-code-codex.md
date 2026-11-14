---
title: Connect Claude Code or Codex
description: Sign in to your Angelos MCP server from the Claude Code or Codex command-line agents with your passkey.
summary: Enable each CLI's pinned identity, add the server, and approve the browser sign-in.
order: 4
category: Get started
---

Claude Code and the Codex CLI connect to Angelos as a remote Streamable HTTP MCP server and sign in through your browser with your Angelos passkey. Neither needs a client secret, a static token, or dynamic client registration. Each CLI identifies itself with a pinned [Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/) and receives the authorization response on a temporary listener on your own computer.

Before you start, you need:

- An Angelos deployment that includes this support (version 0.12.0, currently **Unreleased**; see the [Changelog](/docs/changelog)).
- A working [Connect Your Assistant](/docs/quickstart) setup with an enrolled owner passkey.
- Claude Code or the Codex CLI on the computer where you will use Angelos.

## 1. Enable the CLI identity

**Agent does:** add the switch for each CLI you use to the Production environment, keep the existing client settings, then **redeploy Production**:

| Variable | Value | Pinned client identity |
| --- | --- | --- |
| `ANGELOS_OAUTH_CLAUDE_CODE_CIMD_ENABLED` | `1` | Claude Code: `https://claude.ai/oauth/claude-code-client-metadata` |
| `ANGELOS_OAUTH_CODEX_CIMD_ENABLED` | `1` | Codex CLI: `https://chatgpt.com/oauth/codex/client.json` |

These switches only enable the listed identities. They work alongside `ANGELOS_OAUTH_CHATGPT_CIMD_ENABLED` and any `ANGELOS_OAUTH_CLIENTS_JSON` entries. Check the redeployed server:

```bash
curl -sS https://my-angelos.vercel.app/.well-known/oauth-authorization-server
```

Expect `"client_id_metadata_document_supported":true`, `"authorization_response_iss_parameter_supported":true`, and `"none"` in `token_endpoint_auth_methods_supported`.

## 2. Connect Claude Code

**You do:** add the server once, then sign in:

```bash
claude mcp add --transport http --scope user angelos https://my-angelos.vercel.app/mcp
claude mcp login angelos
```

`--scope user` makes Angelos available in every project. Omit it to add the server to the current project only. Instead of `claude mcp login`, you can run `/mcp` inside a Claude Code session, select `angelos`, and choose its authenticate option.

Your browser opens the Angelos sign-in page. Sign in with your passkey and review the consent screen: the application is **Claude Code**, and the return address is `http://localhost:<port>/callback` (an app on this device). Approve the requested scopes. Claude Code receives the response, stores the tokens, and loads the tools. Run `claude mcp list` to confirm that `angelos` is connected.

Non-interactive `claude -p` runs and the Agent SDK can't open a browser to sign in. Sign in once with `claude mcp login angelos` first. [Claude Code MCP authentication](https://code.claude.com/docs/en/mcp#authenticate-with-remote-mcp-servers)

## 3. Connect Codex

**You do:** add the server:

```bash
codex mcp add angelos --url https://my-angelos.vercel.app/mcp
```

When Codex finds the server's OAuth metadata, it starts the browser sign-in right away. To sign in later or again, run `codex mcp login angelos`. Sign in with your passkey and approve the **Codex** consent screen, whose return address is `http://127.0.0.1:<port>/callback`. Run `codex mcp list`, or `/mcp` in the Codex TUI, to confirm the server is connected.

On a computer without a local browser, run `codex mcp login angelos --no-browser`, open the printed URL elsewhere, and paste the full callback URL back into the terminal. [Codex MCP configuration](https://developers.openai.com/codex/mcp)

Both CLIs request the scopes in the server's initial `WWW-Authenticate` challenge. A full setup with `MCP_OAUTH_INITIAL_SCOPES=mail.read mail.write mail.send` therefore asks for all three. Deselecting scopes on the consent screen grants less; you must sign in again to add them later.

## 4. Verify without changing mail

Ask the agent in a new session:

> Use Angelos to check capabilities and list my mailbox folders. Don't change or send anything.

Confirm the folders belong to the intended mailbox. Before any send, review the prepared message as described in [Writing and sending](/docs/sending-guide).

## Use a predefined client instead

If the metadata identity can't be used, register a predefined public client with a port-free loopback callback. Add it to `ANGELOS_OAUTH_CLIENTS_JSON`, preserving existing entries, and redeploy:

```json
[{"client_id":"angelos-claude-code","client_name":"Claude Code","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"]},
 {"client_id":"angelos-codex","client_name":"Codex","redirect_uris":["http://127.0.0.1/callback"]}]
```

Then add the server with that client ID:

```bash
claude mcp add --transport http --scope user --client-id angelos-claude-code angelos https://my-angelos.vercel.app/mcp
codex mcp add angelos --url https://my-angelos.vercel.app/mcp --oauth-client-id angelos-codex
```

Leave the client secret empty: these are public clients that use PKCE. A port-free loopback callback accepts whatever port the CLI's listener chooses, so a fixed `--callback-port` is optional.

## How the sign-in is protected

- Angelos fetches only the two pinned metadata URLs, and only while their switches are on. A document can list only the callbacks pinned in Angelos, `http://localhost/callback` and `http://127.0.0.1/callback`, and can never add another destination.
- The port chosen at login is accepted as described in [RFC 8252 section 7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3). The scheme, host spelling, path, and query must match exactly, and the code exchange must repeat the exact callback, including its port.
- PKCE S256, the exact `/mcp` resource, and the issuer-bound `iss` response parameter apply as for every other client. See the [OAuth reference](/docs/oauth-reference#client-validation).
- Each sign-in creates its own grant. Review and revoke grants at `/oauth/grants`. `claude mcp logout` and `codex mcp logout` delete only the local tokens; Angelos has no token-revocation endpoint, so revoke the grant there too.
- Turning a switch off denies refresh and the existing access tokens for that identity. Access tokens last five minutes and refresh automatically; a grant expires after 30 days, after which you sign in again.

## Troubleshooting

| What you see | What to check |
| --- | --- |
| Browser shows `{"error":"invalid_client"}` | The CLI's switch is off, Production wasn't redeployed, or the deployment predates 0.12.0. Check the authorization-server metadata from step 1. |
| Claude Code reports that the server does not support dynamic client registration | No metadata identity is enabled. Enable the Claude Code switch, or use a predefined client. |
| The callback page doesn't load after approval | The CLI's listener stopped. Start sign-in again, or paste the full callback URL into the CLI prompt (`--no-browser` for either CLI). |
| `Consent request expired or superseded` | Restart sign-in from the CLI. Each attempt has its own pending request. |
| Tools stop working after about 30 days | The grant expired. Run `claude mcp login angelos` or `codex mcp login angelos`. |
