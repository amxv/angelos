#!/usr/bin/env python3
"""Owner-run initial Microsoft Graph grant. Standard library; no secret logging.

Run --help first. This is an initial-setup helper, not a credential rotation tool.
The owner must register a confidential Web application and complete consent.
It never provisions accounts, changes mailbox content, or deploys configuration.
"""
import argparse
import base64
import getpass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import socketserver
import ssl
import stat
import sys
import threading
import time
import urllib.parse
import warnings

REDIRECT_URI = "http://127.0.0.1:8400/callback"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 8400
CALLBACK_PATH = "/callback"
LOGIN_ROOT = "https://login.microsoftonline.com"
GRAPH_ME = "https://graph.microsoft.com/v1.0/me?$select=id,mail"
SCOPES = ("https://graph.microsoft.com/User.Read",
          "https://graph.microsoft.com/Mail.ReadWrite",
          "https://graph.microsoft.com/Mail.Send", "offline_access")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
MAILBOX = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
CALLBACK_TIMEOUT = 300
REQUEST_TIMEOUT = 20
SOCKET_TIMEOUT = 5
MAX_RESPONSE = 64 * 1024
MAX_CALLBACK_BODY = 32 * 1024
MAX_HEADERS = 16 * 1024
MAX_CREDENTIAL = 16 * 1024
REPO_ROOT = Path(__file__).resolve().parents[1]


class Stop(Exception):
    """Only developer-authored, credential-free messages may be supplied."""


class CallbackRejected(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Stop(message)


def credential(value, label="Credential", limit=MAX_CREDENTIAL):
    # Reject whitespace/control characters before HTTP headers or file output.
    require(isinstance(value, str) and 0 < len(value) <= limit and
            all(33 <= ord(c) <= 126 for c in value),
            label + " is missing or invalid; no configuration was saved.")
    return value


def mailbox(value):
    require(isinstance(value, str) and len(value) <= 254 and
            MAILBOX.fullmatch(value) is not None and ".." not in value,
            "A bare primary mailbox address is required.")
    return value


def identifiers(client_id, tenant_id):
    require(UUID.fullmatch(client_id) is not None, "Client ID must be a UUID.")
    require(tenant_id == "consumers" or UUID.fullmatch(tenant_id) is not None,
            "Tenant ID must be a UUID, or consumers for a personal Microsoft account.")
    return client_id.lower(), tenant_id.lower()


def private_path(path, repo_root=REPO_ROOT):
    """Check resolved destination and repository boundaries without reading files."""
    path = Path(path).expanduser()
    require(path.is_absolute(), "Use an absolute private file path outside the repository.")
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise Stop("Create a private output directory outside the repository first.") from None
    require(repo_root.resolve() not in (parent, *parent.parents),
            "Credential files must be outside the repository.")
    require(not any((p / ".git").exists() for p in (parent, *parent.parents)),
            "Credential files must be outside all Git working trees.")
    require(path.name not in ("", ".", ".."), "A private file name is required.")
    return parent / path.name


def private_directory(path):
    require(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
            "Run this helper on Linux or macOS with POSIX file permissions.")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise Stop("The private directory must be owned by you and have mode 0700.")
        return fd
    except OSError:
        raise Stop("Cannot open the private directory safely.") from None


class PrivateOutput:
    """Hold a checked directory descriptor; O_EXCL prevents overwrite/races."""
    def __init__(self, path, repo_root=REPO_ROOT):
        self.path = private_path(path, repo_root)
        self.fd = private_directory(self.path.parent)
        try:
            os.stat(self.path.name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError:
            self.close()
            raise Stop("Cannot verify the output file safely.") from None
        self.close()
        raise Stop("Output already exists; do not overwrite an existing setup.")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def write(self, values):
        # JSON-style double quoting is supported by dotenv readers. This file is
        # a transfer reference, never a shell script: do not source or execute it.
        text = ("# Private initial Angelos settings. Never commit, print, or attach.\n"
                "# Do not source/execute. Transfer values through a secure settings UI.\n")
        for key, value in values.items():
            require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key), "Invalid configuration key.")
            credential(value, "Configuration value")
            text += key + "=" + json.dumps(value, ensure_ascii=True) + "\n"
        created = False
        try:
            fd = os.open(self.path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            created = True
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(self.fd)
        except FileExistsError:
            raise Stop("Output already exists; no existing file was changed.") from None
        except OSError:
            if created:
                try:
                    os.unlink(self.path.name, dir_fd=self.fd)
                except OSError:
                    pass
            raise Stop("Could not save configuration safely; inspect the private output directory.") from None


def read_private_value(path, label):
    path = private_path(path)
    directory = private_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                    info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in (0o400, 0o600),
                    label + " file must be a private, owned, non-linked 0400 or 0600 file.")
            raw = stream.read(MAX_CREDENTIAL + 3)
        # Permit one editor-added line ending, never extra whitespace/lines.
        if raw.endswith(b"\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n"):
            raw = raw[:-1]
        value = raw.decode("ascii")
    except (OSError, UnicodeError):
        raise Stop("Cannot read the protected " + label.lower() + " file safely.") from None
    finally:
        os.close(directory)
    return credential(value, label)


def read_client_secret(path=None):
    if path is None:
        require(sys.stdin.isatty(),
                "Enter the client secret in an interactive terminal, or use --client-secret-file.")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass("Microsoft client secret (hidden): ")
        except (getpass.GetPassWarning, EOFError, OSError):
            raise Stop("Hidden secret entry is unavailable; use a protected client-secret file.") from None
    else:
        value = read_private_value(path, "Client secret")
    return credential(value, "Client secret")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


class NetworkDeadline:
    """Hard wall-clock limit, including DNS/TLS/headers/slow response bodies.

    This owner-run POSIX CLI does not run network requests in worker threads.
    Fail closed rather than install a process-wide timer from a worker thread or
    overwrite another application's active alarm if imported elsewhere.
    """
    def __enter__(self):
        require(threading.current_thread() is threading.main_thread() and
                hasattr(signal, "setitimer") and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
                "Network requests require an idle main-thread timer on Linux or macOS.")
        self.old_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, self.expired)
        signal.setitimer(signal.ITIMER_REAL, REQUEST_TIMEOUT)
        return self

    def expired(self, signum, frame):
        raise Stop("Microsoft request timed out; no configuration was saved.")

    def __exit__(self, exc_type, exc_value, traceback):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.old_handler)


def request_json(method, url, data=None, headers=None):
    with NetworkDeadline():
        return _request_json(method, url, data, headers)


def tls_context():
    # create_default_context() honors SSLKEYLOGFILE and can write TLS session
    # secrets. Build its verified client equivalent without opt-in key logging.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return context


def _request_json(method, url, data=None, headers=None):
    """Pinned, direct TLS only; no proxy configuration and no redirect following."""
    parsed = urllib.parse.urlsplit(url)
    token_path = re.fullmatch(r"/([^/]+)/oauth2/v2\.0/token", parsed.path)
    valid_token = (parsed.netloc == "login.microsoftonline.com" and token_path is not None and
                   (token_path[1] == "consumers" or UUID.fullmatch(token_path[1]) is not None) and
                   not parsed.query and method == "POST")
    require(parsed.scheme == "https" and not parsed.fragment and
            (valid_token or url == GRAPH_ME and method == "GET"),
            "Unapproved Microsoft endpoint refused.")
    connection = None
    started = time.monotonic()
    try:
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=REQUEST_TIMEOUT,
                                                context=tls_context())
        connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""),
                           body=data, headers=headers or {})
        response = connection.getresponse()
        require(response.status == 200,
                "Microsoft request failed; check registration, consent, and account policy.")
        require(response.getheader("Content-Type", "").split(";", 1)[0].lower() == "application/json",
                "Microsoft returned an unexpected response type.")
        length = response.getheader("Content-Length")
        require(length is None or length.isdigit() and int(length) <= MAX_RESPONSE,
                "Microsoft response exceeded the safe size limit.")
        chunks, count = [], 0
        while True:
            remaining = REQUEST_TIMEOUT - (time.monotonic() - started)
            require(remaining > 0, "Microsoft request timed out; no configuration was saved.")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(4096, MAX_RESPONSE + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            require(count <= MAX_RESPONSE, "Microsoft response exceeded the safe size limit.")
            chunks.append(chunk)
        result = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_object)
        require(isinstance(result, dict), "Microsoft returned an invalid response.")
        return result
    except Stop:
        raise
    except (OSError, http.client.HTTPException, ValueError, UnicodeError):
        raise Stop("Microsoft connection or response failed; no credentials were logged.") from None
    finally:
        if connection is not None:
            connection.close()


class PendingGrant:
    def __init__(self, client_id, tenant_id, clock=time.monotonic):
        self.client_id, self.tenant_id = identifiers(client_id, tenant_id)
        self.clock = clock
        self.deadline = clock() + CALLBACK_TIMEOUT
        self.state = secrets.token_urlsafe(32)
        self.verifier = secrets.token_urlsafe(64)
        self.consumed = False
        self.exchange_started = False

    def authorization_url(self):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        return LOGIN_ROOT + "/" + self.tenant_id + "/oauth2/v2.0/authorize?" + urllib.parse.urlencode({
            "client_id": self.client_id, "response_type": "code", "redirect_uri": REDIRECT_URI,
            "response_mode": "form_post", "scope": " ".join(SCOPES), "state": self.state,
            "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"})

    def accept(self, body):
        if self.consumed or self.clock() >= self.deadline or len(body) > MAX_CALLBACK_BODY:
            raise CallbackRejected()
        try:
            text = body.decode("ascii")
            if re.search(r"%(?![0-9a-fA-F]{2})", text):
                raise ValueError()
            fields = urllib.parse.parse_qs(text, keep_blank_values=True, strict_parsing=True,
                                          encoding="utf-8", errors="strict", max_num_fields=12)
            if any(len(v) != 1 for v in fields.values()):
                raise ValueError()
            state = fields.get("state", [""])[0]
            if not state.isascii() or not secrets.compare_digest(state, self.state):
                raise ValueError()
        except (ValueError, UnicodeError):
            raise CallbackRejected() from None
        # A matching state is single use, including denied or malformed grants.
        self.consumed = True
        if "error" in fields:
            raise Stop("Microsoft authorization was declined or failed; no configuration was saved.")
        code = fields.get("code", [""])[0]
        try:
            return credential(code, "Authorization response")
        except Stop:
            raise CallbackRejected() from None


def read_callback(sock, deadline):
    """Minimal bounded HTTP parser: one POST, no chunked or query credentials."""
    end = min(deadline, time.monotonic() + SOCKET_TIMEOUT)

    def receive():
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise CallbackRejected()
        sock.settimeout(remaining)
        data = sock.recv(4096)
        if not data:
            raise CallbackRejected()
        return data

    data = b""
    while b"\r\n\r\n" not in data:
        data += receive()
        if len(data) > MAX_HEADERS + 4096:
            raise CallbackRejected()
    head, body = data.split(b"\r\n\r\n", 1)
    if len(head) > MAX_HEADERS:
        raise CallbackRejected()
    try:
        lines = head.decode("ascii").split("\r\n")
        if lines[0] not in ("POST /callback HTTP/1.1", "POST /callback HTTP/1.0") or len(lines) > 65:
            raise ValueError()
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            if not re.fullmatch(r"[A-Za-z0-9-]+", name) or name.lower() in headers:
                raise ValueError()
            headers[name.lower()] = value.strip()
        if headers.get("host") != "127.0.0.1:8400" or "transfer-encoding" in headers:
            raise ValueError()
        if headers.get("content-type", "").split(";", 1)[0].lower() != "application/x-www-form-urlencoded":
            raise ValueError()
        length = headers.get("content-length", "")
        if not length.isdigit() or not 0 < int(length) <= MAX_CALLBACK_BODY:
            raise ValueError()
        length = int(length)
    except ValueError:
        raise CallbackRejected() from None
    while len(body) < length:
        body += receive()
    if len(body) != length:
        raise CallbackRejected()
    return body


class CallbackHandler(socketserver.BaseRequestHandler):
    def handle(self):
        message = b"Request rejected. Return to the terminal.\n"
        status = b"400 Bad Request"
        try:
            body = read_callback(self.request, self.server.grant.deadline)
            self.server.code = self.server.grant.accept(body)
            status = b"200 OK"
            message = b"Authorization received. You may close this tab and return to the terminal.\n"
        except Stop as error:
            self.server.failure = error
            message = b"Authorization failed. Return to the terminal.\n"
        except (CallbackRejected, OSError, ValueError):
            pass
        try:
            self.request.settimeout(1)
            self.request.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Type: text/plain; charset=utf-8\r\n"
                                 b"Cache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\n"
                                 b"Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
                                 b"X-Content-Type-Options: nosniff\r\nConnection: close\r\nContent-Length: " +
                                 str(len(message)).encode("ascii") + b"\r\n\r\n" + message)
        except OSError:
            pass


class CallbackServer(socketserver.TCPServer):
    allow_reuse_address = False
    request_queue_size = 5

    def __init__(self, grant):
        self.grant, self.code, self.failure = grant, None, None
        try:
            super().__init__((CALLBACK_HOST, CALLBACK_PORT), CallbackHandler)
        except OSError:
            raise Stop("Cannot bind 127.0.0.1:8400; close the conflicting program and retry.") from None

    def handle_error(self, request, client_address):
        # socketserver's default would print tracebacks containing local values.
        self.failure = Stop("The local callback failed; no credentials were logged.")

    def wait_for_code(self):
        while self.code is None and self.failure is None:
            remaining = self.grant.deadline - self.grant.clock()
            require(remaining > 0 and not self.grant.consumed,
                    "Authorization expired or was invalid; rerun the helper for a new grant.")
            self.timeout = min(remaining, 1)
            self.handle_request()
        if self.failure:
            raise self.failure
        return self.code


def exchange(grant, code, secret, expected_mailbox, encryption_key, transport=request_json):
    require(grant.consumed and not grant.exchange_started and grant.clock() < grant.deadline,
            "Authorization is missing or expired; start a new grant.")
    grant.exchange_started = True
    credential(secret, "Client secret")
    credential(code, "Authorization response")
    require(re.fullmatch(r"[0-9a-fA-F]{64}", encryption_key),
            "Token encryption key must be 32 random bytes encoded as 64 hex characters.")
    payload = urllib.parse.urlencode({"client_id": grant.client_id, "client_secret": secret,
                                     "grant_type": "authorization_code", "code": code,
                                     "redirect_uri": REDIRECT_URI, "code_verifier": grant.verifier,
                                     "scope": " ".join(SCOPES)}).encode("ascii")
    tokens = transport("POST", LOGIN_ROOT + "/" + grant.tenant_id + "/oauth2/v2.0/token", payload,
                       {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    require(isinstance(tokens, dict) and isinstance(tokens.get("token_type"), str) and
            tokens["token_type"].lower() == "bearer", "Microsoft did not return a bearer token.")
    access = credential(tokens.get("access_token"), "Access token")
    refresh = credential(tokens.get("refresh_token"), "Refresh token")
    # Require the same explicit, case-sensitive Graph permissions as the server.
    # Fail closed if omitted even though OAuth permits scope omission. A refresh
    # token proves offline_access; it need not be in the access-token scope list.
    scope = tokens.get("scope")
    require(isinstance(scope, str), "Microsoft returned missing or invalid permission data.")
    granted = {s.removeprefix("https://graph.microsoft.com/") for s in scope.split()}
    require({"User.Read", "Mail.ReadWrite", "Mail.Send"} <= granted,
            "Microsoft did not grant all required delegated permissions.")
    identity = transport("GET", GRAPH_ME, None,
                         {"Authorization": "Bearer " + access, "Accept": "application/json"})
    require(isinstance(identity, dict), "Microsoft returned an invalid identity.")
    account_id = credential(identity.get("id"), "Microsoft account ID", limit=256)
    verified_mail = mailbox(identity.get("mail"))
    require(verified_mail.lower() == mailbox(expected_mailbox).lower(),
            "The authorized primary mailbox does not match --mailbox; no configuration was saved.")
    return {"MAIL_PROVIDER": "microsoft", "MAIL_AUTH_MODE": "microsoft_graph",
            "MAIL_USERNAME": verified_mail, "MAIL_FROM": verified_mail,
            "MICROSOFT_CLIENT_ID": grant.client_id, "MICROSOFT_CLIENT_SECRET": secret,
            "MICROSOFT_REFRESH_TOKEN": refresh, "MICROSOFT_TENANT_ID": grant.tenant_id,
            "MICROSOFT_ACCOUNT_ID": account_id, "MICROSOFT_TOKEN_ENCRYPTION_KEY": encryption_key}


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unknown arguments, potentially pasted secrets.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments. Use --help; never pass a secret as an argument.\n")


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--client-id", required=True, help="Microsoft application (client) UUID")
    parser.add_argument("--tenant-id", required=True, help="Directory UUID, or consumers for Outlook.com")
    parser.add_argument("--mailbox", required=True, help="Expected primary mailbox, verified against Graph /me.mail")
    parser.add_argument("--output", required=True, help="New absolute file path in an existing owned 0700 directory outside any repository")
    parser.add_argument("--client-secret-file", help="Optional absolute path to an owned 0400/0600 secret file in a private 0700 directory; otherwise hidden terminal prompt")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--new-instance", action="store_true", help="Initial setup only: generate a new refresh-token encryption key")
    mode.add_argument("--token-encryption-key-file", help="Regrant: preserve the existing 64-hex encryption key from a protected file")
    args = parser.parse_args(argv)
    output = None
    try:
        client_id, tenant_id = identifiers(args.client_id, args.tenant_id)
        expected_mail = mailbox(args.mailbox)
        output = PrivateOutput(args.output)
        secret = read_client_secret(args.client_secret_file)
        encryption_key = (secrets.token_hex(32) if args.new_instance else
                          read_private_value(args.token_encryption_key_file, "Token encryption key"))
        require(re.fullmatch(r"[0-9a-fA-F]{64}", encryption_key),
                "Token encryption key must be 32 random bytes encoded as 64 hex characters.")
        grant = PendingGrant(client_id, tenant_id)
        # Bind before presenting the URL so a competing listener fails closed.
        with CallbackServer(grant) as callback:
            if args.new_instance:
                print("NEW INSTANCE: generating a new encryption key. Do not replace an existing instance key.")
            else:
                print("REGRANT: preserving the encryption key from the protected input file.")
            print("Open this Microsoft sign-in URL in your browser on THIS computer within 5 minutes.")
            print("You must complete sign-in and delegated mail consent yourself.")
            print("The registered confidential Web redirect URI must be exactly " + REDIRECT_URI)
            print(grant.authorization_url(), flush=True)
            code = callback.wait_for_code()
        values = exchange(grant, code, secret, expected_mail, encryption_key)
        output.write(values)
        print("Verified the intended primary mailbox. Saved the new owner-only configuration file.")
        print("Use a secure settings UI to transfer values. Never paste the file into chat, print, commit, source, or execute it.")
        return 0
    except Stop as error:
        print("Stopped: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled. No existing configuration was changed.", file=sys.stderr)
        return 130
    except Exception:
        # Secret material can be present in network errors or third-party bodies.
        # Never format arbitrary exceptions, request objects, or tracebacks here.
        print("Stopped: Unexpected failure; no credentials were logged. Inspect the private output directory.", file=sys.stderr)
        return 1
    finally:
        if output is not None:
            output.close()


if __name__ == "__main__":
    sys.exit(main())
