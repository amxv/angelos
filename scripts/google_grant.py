#!/usr/bin/env python3
"""Owner-run initial Google Gmail grant. Standard library; no secret logging.

Run --help first. This is an initial-setup helper, not a credential rotation tool.
The owner must register a confidential Web application, enable the Gmail API,
and complete consent on the same computer. Google account, administrator,
verification, and External Testing (7-day refresh token) restrictions still apply.
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
import socketserver
import ssl
import stat
import sys
import threading
import time
import urllib.parse
import warnings

REDIRECT_URI = "http://127.0.0.1:8401/callback"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 8401
CALLBACK_PATH = "/callback"
AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GMAIL_PROFILE = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
SCOPES = ("https://mail.google.com/",)
CLIENT_ID = re.compile(r"[A-Za-z0-9-]+\.apps\.googleusercontent\.com\Z")
MAILBOX = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
CALLBACK_TIMEOUT = 300
REQUEST_TIMEOUT = 20
SOCKET_TIMEOUT = 5
MAX_RESPONSE = 64 * 1024
MAX_CALLBACK_QUERY = 8 * 1024
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


def identifier(client_id):
    require(isinstance(client_id, str) and len(client_id) <= 256 and
            CLIENT_ID.fullmatch(client_id) is not None,
            "Client ID must be a Google OAuth client ending in .apps.googleusercontent.com.")
    return client_id


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
                value = getpass.getpass("Google client secret (hidden): ")
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
        raise Stop("Google request timed out; no configuration was saved.")

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
    require((url == TOKEN_ENDPOINT and method == "POST") or
            (url == GMAIL_PROFILE and method == "GET"),
            "Unapproved Google endpoint refused.")
    connection = None
    started = time.monotonic()
    try:
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=REQUEST_TIMEOUT,
                                                context=tls_context())
        connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""),
                           body=data, headers=headers or {})
        response = connection.getresponse()
        if url == GMAIL_PROFILE:
            require(response.status == 200,
                    "Gmail profile check failed; enable the Gmail API in this OAuth client's project "
                    "and check Gmail access and administrator policy. No configuration was saved.")
        else:
            require(response.status == 200,
                    "Google token request failed; check Web client registration, consent, and account policy.")
        require(response.getheader("Content-Type", "").split(";", 1)[0].lower() == "application/json",
                "Google returned an unexpected response type.")
        length = response.getheader("Content-Length")
        require(length is None or length.isdigit() and int(length) <= MAX_RESPONSE,
                "Google response exceeded the safe size limit.")
        chunks, count = [], 0
        while True:
            remaining = REQUEST_TIMEOUT - (time.monotonic() - started)
            require(remaining > 0, "Google request timed out; no configuration was saved.")
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(4096, MAX_RESPONSE + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            require(count <= MAX_RESPONSE, "Google response exceeded the safe size limit.")
            chunks.append(chunk)
        result = json.loads(b"".join(chunks).decode("utf-8"), object_pairs_hook=unique_object)
        require(isinstance(result, dict), "Google returned an invalid response.")
        return result
    except Stop:
        raise
    except (OSError, http.client.HTTPException, ValueError, UnicodeError):
        raise Stop("Google connection or response failed; no credentials were logged.") from None
    finally:
        if connection is not None:
            connection.close()


class PendingGrant:
    def __init__(self, client_id, clock=time.monotonic):
        self.client_id = identifier(client_id)
        self.clock = clock
        self.deadline = clock() + CALLBACK_TIMEOUT
        self.state = secrets.token_urlsafe(32)
        self.verifier = secrets.token_urlsafe(64)
        self.consumed = False
        self.exchange_started = False

    def authorization_url(self):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        return AUTHORIZATION_ENDPOINT + "?" + urllib.parse.urlencode({
            "client_id": self.client_id, "response_type": "code", "redirect_uri": REDIRECT_URI,
            "scope": " ".join(SCOPES), "state": self.state,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "access_type": "offline", "include_granted_scopes": "false",
            "prompt": "consent select_account"})

    def accept(self, query):
        if self.consumed or self.clock() >= self.deadline or len(query) > MAX_CALLBACK_QUERY:
            raise CallbackRejected()
        try:
            text = query.decode("ascii")
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
            raise Stop("Google authorization was declined or failed; no configuration was saved.")
        code = fields.get("code", [""])[0]
        try:
            return credential(code, "Authorization response")
        except Stop:
            raise CallbackRejected() from None


def read_callback(sock, deadline):
    """Minimal bounded HTTP parser: fixed local GET, no bodies or redirects.

    Google returns the code in the query; never log or echo this request target.
    The callback scope parameter is untrusted. Only the token response is used.
    """
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
    if len(head) > MAX_HEADERS or body:
        raise CallbackRejected()
    try:
        lines = head.decode("ascii").split("\r\n")
        method, target, version = lines[0].split(" ")
        if method != "GET" or version not in ("HTTP/1.1", "HTTP/1.0") or len(lines) > 65:
            raise ValueError()
        path, separator, query = target.partition("?")
        if path != CALLBACK_PATH or not separator or not query or "#" in query:
            raise ValueError()
        if len(query) > MAX_CALLBACK_QUERY or any(not 33 <= ord(c) <= 126 for c in query):
            raise ValueError()
        headers = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            if not re.fullmatch(r"[A-Za-z0-9-]+", name) or name.lower() in headers:
                raise ValueError()
            if any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value):
                raise ValueError()
            headers[name.lower()] = value.strip()
        if headers.get("host") != "127.0.0.1:8401" or "transfer-encoding" in headers:
            raise ValueError()
        if headers.get("content-length", "0") != "0":
            raise ValueError()
    except ValueError:
        raise CallbackRejected() from None
    return query.encode("ascii")


class CallbackHandler(socketserver.BaseRequestHandler):
    def handle(self):
        message = b"Request rejected. Return to the terminal.\n"
        status = b"400 Bad Request"
        try:
            query = read_callback(self.request, self.server.grant.deadline)
            self.server.code = self.server.grant.accept(query)
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
            raise Stop("Cannot bind 127.0.0.1:8401; close the conflicting program and retry.") from None

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


def exchange(grant, code, secret, expected_mailbox, transport=request_json):
    require(grant.consumed and not grant.exchange_started and grant.clock() < grant.deadline,
            "Authorization is missing or expired; start a new grant.")
    grant.exchange_started = True
    credential(secret, "Client secret")
    credential(code, "Authorization response")
    expected_mailbox = mailbox(expected_mailbox)
    payload = urllib.parse.urlencode({"client_id": grant.client_id, "client_secret": secret,
                                     "grant_type": "authorization_code", "code": code,
                                     "redirect_uri": REDIRECT_URI,
                                     "code_verifier": grant.verifier}).encode("ascii")
    tokens = transport("POST", TOKEN_ENDPOINT, payload,
                       {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    require(isinstance(tokens, dict) and isinstance(tokens.get("token_type"), str) and
            tokens["token_type"].lower() == "bearer", "Google did not return a bearer token.")
    access = credential(tokens.get("access_token"), "Access token")
    refresh = credential(tokens.get("refresh_token"), "Refresh token")
    # The callback's scope is not authoritative. Require Google's explicit token
    # scope, even though OAuth permits its omission, and reject broader grants.
    scope = tokens.get("scope")
    require(isinstance(scope, str) and len(scope) <= MAX_CREDENTIAL and
            all(32 <= ord(c) <= 126 for c in scope),
            "Google returned missing or invalid permission data.")
    require(set(scope.split(" ")) == set(SCOPES),
            "Google did not return exactly the required full-mail Gmail permission.")
    identity = transport("GET", GMAIL_PROFILE, None,
                         {"Authorization": "Bearer " + access, "Accept": "application/json"})
    require(isinstance(identity, dict), "Google returned an invalid Gmail profile.")
    verified_mail = mailbox(identity.get("emailAddress"))
    require(verified_mail.lower() == expected_mailbox.lower(),
            "The authorized primary mailbox does not match --mailbox; no configuration was saved.")
    return {"MAIL_PROVIDER": "gmail", "MAIL_AUTH_MODE": "google_oauth2",
            "MAIL_USERNAME": verified_mail, "MAIL_FROM": verified_mail,
            "GOOGLE_CLIENT_ID": grant.client_id, "GOOGLE_CLIENT_SECRET": secret,
            "GOOGLE_REFRESH_TOKEN": refresh}


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes unknown arguments, potentially pasted secrets.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments. Use --help; never pass a secret as an argument.\n")


def main(argv=None):
    parser = SafeArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--client-id", required=True, help="Google confidential Web OAuth client ID ending in .apps.googleusercontent.com")
    parser.add_argument("--mailbox", required=True, help="Expected primary mailbox, verified against Gmail users/me/profile.emailAddress")
    parser.add_argument("--output", required=True, help="New absolute file path in an existing owned 0700 directory outside any repository")
    parser.add_argument("--client-secret-file", help="Optional absolute path to an owned 0400/0600 secret file in a private 0700 directory; otherwise hidden terminal prompt")
    args = parser.parse_args(argv)
    output = None
    try:
        client_id = identifier(args.client_id)
        expected_mail = mailbox(args.mailbox)
        output = PrivateOutput(args.output)
        secret = read_client_secret(args.client_secret_file)
        grant = PendingGrant(client_id)
        # Bind before presenting the URL so a competing listener fails closed.
        with CallbackServer(grant) as callback:
            print("Open this Google sign-in URL in your browser on THIS computer within 5 minutes.")
            print("You must complete sign-in and full-mail Gmail consent yourself.")
            print("The registered confidential Web redirect URI must be exactly " + REDIRECT_URI)
            print("Gmail API must be enabled in the same Cloud project. Keep the callback URL private.")
            print(grant.authorization_url(), flush=True)
            code = callback.wait_for_code()
        values = exchange(grant, code, secret, expected_mail)
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
