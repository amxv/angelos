"""Synthetic fixtures only. Never contacts Microsoft or uses real credentials."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import stat
import ssl
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import urllib.parse

import microsoft_grant as grant

CLIENT = "11111111-2222-3333-4444-555555555555"
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
SECRET = "synthetic-client-secret"
CODE = "synthetic-code"
ACCESS = "synthetic-access-token"
REFRESH = "synthetic-refresh-token"
KEY = "ab" * 32
MAIL = "person@example.test"
ACCOUNT = "synthetic-account-id"


@contextlib.contextmanager
def private_fixture():
    # Some test sandboxes put every writable root inside an ambient Git checkout.
    # Ignore only outer sandbox .git markers for these synthetic credentials;
    # real helper behavior and fixture-created nested repositories stay unchanged.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        ambient = {p / ".git" for p in root.parents}
        exists = Path.exists
        def fixture_exists(path):
            return False if path in ambient else exists(path)
        with patch.object(Path, "exists", fixture_exists):
            yield directory


def pending(clock=lambda: 100):
    return grant.PendingGrant(CLIENT, "consumers", clock=clock)


def callback(grant_state, **extra):
    return urllib.parse.urlencode({"code": CODE, "state": grant_state.state, **extra}).encode()


def accepted():
    state = pending()
    code = state.accept(callback(state))
    return state, code


def token_response(**changes):
    return {"access_token": ACCESS, "refresh_token": REFRESH, "token_type": "Bearer",
            "scope": "User.Read Mail.ReadWrite Mail.Send", **changes}


class SyntheticTransport:
    def __init__(self, tokens=None, identity=None):
        self.calls = []
        self.tokens = token_response() if tokens is None else tokens
        self.identity = {"id": ACCOUNT, "mail": MAIL} if identity is None else identity

    def __call__(self, method, url, data=None, headers=None):
        self.calls.append((method, url, data, headers))
        return self.tokens if method == "POST" else self.identity


class GrantTests(unittest.TestCase):
    def test_authorization_url_is_pinned_pkce_form_post(self):
        state = pending()
        url = urllib.parse.urlsplit(state.authorization_url())
        self.assertEqual((url.scheme, url.netloc, url.path),
                         ("https", "login.microsoftonline.com", "/consumers/oauth2/v2.0/authorize"))
        fields = urllib.parse.parse_qs(url.query)
        self.assertEqual(fields["redirect_uri"], ["http://127.0.0.1:8400/callback"])
        self.assertEqual(fields["response_mode"], ["form_post"])
        self.assertEqual(fields["response_type"], ["code"])
        self.assertEqual(fields["scope"], [" ".join(grant.SCOPES)])
        self.assertEqual(fields["code_challenge_method"], ["S256"])
        expected = base64.urlsafe_b64encode(hashlib.sha256(state.verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(fields["code_challenge"], [expected])
        for name in ("client_secret", "code", "code_verifier", "login_hint", "access_token", "refresh_token"):
            self.assertNotIn(name, fields)
        self.assertGreaterEqual(len(state.state), 43)
        self.assertTrue(43 <= len(state.verifier) <= 128)
        other = pending()
        self.assertNotEqual(state.state, other.state)
        self.assertNotEqual(state.verifier, other.verifier)

    def test_only_explicit_tenant_ids_and_consumers(self):
        self.assertEqual(grant.identifiers(CLIENT.upper(), TENANT.upper()), (CLIENT, TENANT))
        for tenant in ("common", "organizations", "example.com", "CONSUMERS", "../consumers", "consumers?secret=x", TENANT + "\n"):
            with self.subTest(tenant=tenant), self.assertRaises(grant.Stop):
                grant.identifiers(CLIENT, tenant)
        for client in ("", "synthetic-secret", CLIENT + "\n", "{" + CLIENT + "}"):
            with self.assertRaises(grant.Stop):
                grant.identifiers(client, "consumers")

    def test_success_and_single_use_state(self):
        state = pending()
        self.assertEqual(state.accept(callback(state)), CODE)
        self.assertTrue(state.consumed)
        with self.assertRaises(grant.CallbackRejected):
            state.accept(callback(state))

    def test_wrong_or_missing_state_does_not_consume(self):
        state = pending()
        for data in (b"code=synthetic", callback(state, state="incorrect"), callback(state) + b"&state=duplicate",
                     b"state=%ff&code=synthetic", b"state=%ZZ&code=synthetic", b"broken", b"x=1&" * 20,
                     b"x" * (grant.MAX_CALLBACK_BODY + 1)):
            with self.subTest(data=data[:30]), self.assertRaises(grant.CallbackRejected):
                state.accept(data)
            self.assertFalse(state.consumed)
        self.assertEqual(state.accept(callback(state)), CODE)

    def test_expired_state(self):
        now = [100]
        state = pending(clock=lambda: now[0])
        now[0] += grant.CALLBACK_TIMEOUT
        with self.assertRaises(grant.CallbackRejected):
            state.accept(callback(state))

    def test_denied_grant_is_sanitized_and_consumed(self):
        state = pending()
        body = callback(state, error="access_denied", error_description=SECRET + ACCESS)
        with self.assertRaises(grant.Stop) as caught:
            state.accept(body)
        self.assertTrue(state.consumed)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn(ACCESS, str(caught.exception))

    def test_matched_state_invalid_code_is_consumed(self):
        state = pending()
        with self.assertRaises(grant.CallbackRejected):
            state.accept(callback(state, code="bad\ncode"))
        self.assertTrue(state.consumed)

    def test_exchange_uses_form_body_and_verifies_me(self):
        state, code = accepted()
        transport = SyntheticTransport(identity={"id": ACCOUNT, "mail": "Person@example.test"})
        values = grant.exchange(state, code, SECRET, MAIL, KEY, transport)
        method, url, data, headers = transport.calls[0]
        self.assertEqual((method, url), ("POST", "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"))
        body = urllib.parse.parse_qs(data.decode())
        self.assertEqual(body["client_secret"], [SECRET])
        self.assertEqual(body["code"], [CODE])
        self.assertEqual(body["code_verifier"], [state.verifier])
        self.assertEqual(body["redirect_uri"], [grant.REDIRECT_URI])
        self.assertEqual(body["grant_type"], ["authorization_code"])
        self.assertEqual(transport.calls[1], ("GET", grant.GRAPH_ME, None,
                                            {"Authorization": "Bearer " + ACCESS, "Accept": "application/json"}))
        self.assertEqual(values["MAIL_USERNAME"], "Person@example.test")
        self.assertEqual(values["MAIL_FROM"], "Person@example.test")
        self.assertEqual(values["MICROSOFT_ACCOUNT_ID"], ACCOUNT)
        self.assertEqual(values["MICROSOFT_TOKEN_ENCRYPTION_KEY"], KEY)
        self.assertNotIn("MICROSOFT_ACCESS_TOKEN", values)
        self.assertEqual(len(values), 10)
        for _, request_url, _, _ in transport.calls:
            for secret in (SECRET, CODE, ACCESS, REFRESH, state.verifier):
                self.assertNotIn(secret, request_url)

    def test_exchange_at_most_once(self):
        state, code = accepted()
        transport = SyntheticTransport()
        grant.exchange(state, code, SECRET, MAIL, KEY, transport)
        with self.assertRaises(grant.Stop):
            grant.exchange(state, code, SECRET, MAIL, KEY, transport)
        self.assertEqual(len(transport.calls), 2)

    def test_exchange_rejects_missing_or_expired_state_before_network(self):
        state = pending()
        transport = SyntheticTransport()
        with self.assertRaises(grant.Stop):
            grant.exchange(state, CODE, SECRET, MAIL, KEY, transport)
        state, code = accepted()
        state.deadline = 99
        with self.assertRaises(grant.Stop):
            grant.exchange(state, code, SECRET, MAIL, KEY, transport)
        self.assertEqual(transport.calls, [])

    def test_required_tokens_and_scopes_fail_closed(self):
        for change in ({"access_token": None}, {"access_token": "bad\r\nheader"}, {"refresh_token": ""},
                       {"token_type": "MAC"}, {"token_type": []}, {"scope": "Mail.ReadWrite Mail.Send"},
                       {"scope": ["User.Read"]}, {"scope": "User.Read Mail.Read Mail.Send"}):
            with self.subTest(change=change), self.assertRaises(grant.Stop):
                state, code = accepted()
                grant.exchange(state, code, SECRET, MAIL, KEY, SyntheticTransport(tokens=token_response(**change)))

    def test_missing_or_case_changed_scope_fails_closed(self):
        tokens = token_response()
        del tokens["scope"]
        for response in (tokens, token_response(scope="user.read Mail.ReadWrite Mail.Send")):
            state, code = accepted()
            with self.assertRaises(grant.Stop):
                grant.exchange(state, code, SECRET, MAIL, KEY, SyntheticTransport(tokens=response))

    def test_qualified_scope_supported(self):
        state, code = accepted()
        grant.exchange(state, code, SECRET, MAIL, KEY, SyntheticTransport(tokens=token_response(scope=" ".join(grant.SCOPES))))

    def test_identity_requires_id_primary_mail_and_expected_account(self):
        for identity in ({"id": "", "mail": MAIL}, {"id": ACCOUNT, "mail": None, "userPrincipalName": MAIL},
                         {"id": ACCOUNT, "mail": "wrong@example.test"}, {"id": "x" * 257, "mail": MAIL},
                         {"id": "bad\nvalue", "mail": MAIL}, {"id": ACCOUNT, "mail": "Name <person@example.test>"},
                         {"id": ACCOUNT, "mail": "bad\n@example.test"}):
            with self.subTest(identity=identity), self.assertRaises(grant.Stop):
                state, code = accepted()
                grant.exchange(state, code, SECRET, MAIL, KEY, SyntheticTransport(identity=identity))

    def test_invalid_key_stops_before_network(self):
        for key in ("", "ab" * 31, "z" * 64, KEY + "\n"):
            state, code = accepted()
            transport = SyntheticTransport()
            with self.assertRaises(grant.Stop):
                grant.exchange(state, code, SECRET, MAIL, key, transport)
            self.assertEqual(transport.calls, [])


class SocketFixtures(unittest.TestCase):
    def wire(self, body, **headers):
        merged = {"Host": "127.0.0.1:8400", "Content-Type": "application/x-www-form-urlencoded",
                  "Content-Length": str(len(body)), **headers}
        return ("POST /callback HTTP/1.1\r\n" + "\r\n".join(k + ": " + v for k, v in merged.items()) + "\r\n\r\n").encode() + body

    def parse(self, wire, shutdown=True):
        server, client = socket.socketpair()
        try:
            client.sendall(wire)
            if shutdown:
                client.shutdown(socket.SHUT_WR)
            return grant.read_callback(server, time.monotonic() + 2)
        finally:
            client.close()
            server.close()

    def test_local_callback_parser(self):
        body = callback(pending())
        self.assertEqual(self.parse(self.wire(body)), body)

    def test_callback_rejects_host_path_method_query_and_duplicates(self):
        original = self.wire(b"code=synthetic&state=x")
        fixtures = [original.replace(b"POST ", b"GET "),
                    original.replace(b"/callback ", b"/callback?code=synthetic "),
                    original.replace(b"127.0.0.1:8400", b"evil.example:8400"),
                    original.replace(b"Host:", b" Host:"),
                    original.replace(b"Host:", b"HOST: bad\r\nHost:"),
                    original.replace(b"Content-Length:", b"Transfer-Encoding: chunked\r\nContent-Length:"),
                    original.replace(b"Content-Length:", b"content-length: 0\r\nContent-Length:"),
                    original.replace(b"application/x-www-form-urlencoded", b"text/plain"),
                    original + b"extra"]
        for wire in fixtures:
            with self.subTest(wire=wire[:60]), self.assertRaises(grant.CallbackRejected):
                self.parse(wire)

    def test_oversized_headers_and_body(self):
        for wire in (b"POST /callback HTTP/1.1\r\nX: " + b"x" * (grant.MAX_HEADERS + 5000),
                     self.wire(b"small", **{"Content-Length": str(grant.MAX_CALLBACK_BODY + 1)}),
                     self.wire(b"small", **{"Content-Length": "-1"}),
                     self.wire(b"small", **{"Content-Length": "100"})):
            with self.assertRaises(grant.CallbackRejected):
                self.parse(wire)

    def test_callback_timeout_and_disconnected_clients(self):
        server, client = socket.socketpair()
        try:
            with self.assertRaises(grant.CallbackRejected):
                grant.read_callback(server, time.monotonic() - 1)
            client.close()
            with self.assertRaises(grant.CallbackRejected):
                grant.read_callback(server, time.monotonic() + 1)
        finally:
            server.close()
            client.close()

    def test_listener_only_binds_fixed_loopback(self):
        with patch.object(socketserver := grant.socketserver.TCPServer, "__init__", return_value=None) as bind:
            grant.CallbackServer(pending())
        self.assertEqual(bind.call_args.args[0], ("127.0.0.1", 8400))

    def test_callback_handler_never_reflects_or_logs_secrets(self):
        state = pending(clock=time.monotonic)
        server = MagicMock(grant=state, code=None, failure=None)
        left, right = socket.socketpair()
        try:
            body = callback(state)
            right.sendall(self.wire(body))
            with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                grant.CallbackHandler(left, ("127.0.0.1", 1), server)
            response = right.recv(4096).decode()
            self.assertTrue(response.startswith("HTTP/1.1 200"))
            for secret in (CODE, SECRET, state.state):
                self.assertNotIn(secret, response + stdout.getvalue() + stderr.getvalue())
            self.assertIn("Cache-Control: no-store", response)
            self.assertIn("Referrer-Policy: no-referrer", response)
            self.assertEqual(server.code, CODE)
        finally:
            right.close()
            left.close()


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = private_fixture()
        self.directory = Path(self.temp.__enter__())
        self.path = self.directory / "new.env"

    def tearDown(self):
        self.temp.__exit__(None, None, None)

    def test_output_new_owner_only_and_never_overwritten(self):
        output = grant.PrivateOutput(self.path)
        try:
            output.write({"VALUE": SECRET, "SPECIAL": "quote\"and$(not-a-command)"})
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            saved = self.path.read_text()
            self.assertIn('VALUE="' + SECRET + '"', saved)
            self.assertIn("Do not source/execute", saved)
            with self.assertRaises(grant.Stop):
                output.write({"VALUE": "changed"})
            self.assertEqual(self.path.read_text(), saved)
        finally:
            output.close()
        with self.assertRaises(grant.Stop):
            grant.PrivateOutput(self.path)

    def test_output_refuses_symlink_and_existing_race(self):
        output = grant.PrivateOutput(self.path)
        other = self.directory / "existing"
        other.write_text("keep")
        self.path.symlink_to(other)
        try:
            with self.assertRaises(grant.Stop):
                output.write({"VALUE": SECRET})
            self.assertEqual(other.read_text(), "keep")
        finally:
            output.close()
        with self.assertRaises(grant.Stop):
            grant.PrivateOutput(self.path)

    def test_missing_public_foreign_or_repository_directories(self):
        for mode in (0o755, 0o750, 0o770):
            self.directory.chmod(mode)
            with self.assertRaises(grant.Stop):
                grant.PrivateOutput(self.path)
        self.directory.chmod(0o700)
        with patch.object(grant.os, "getuid", return_value=os.getuid() + 1), self.assertRaises(grant.Stop):
            grant.PrivateOutput(self.path)
        with self.assertRaises(grant.Stop):
            grant.PrivateOutput(self.directory / "missing" / "out")
        with self.assertRaises(grant.Stop):
            grant.PrivateOutput(Path("relative.env"))
        with self.assertRaises(grant.Stop):
            grant.PrivateOutput(self.path, repo_root=self.directory)
        (self.directory / ".git").mkdir()
        with self.assertRaises(grant.Stop):
            grant.PrivateOutput(self.path)

    def test_resolved_symlink_parent_cannot_enter_repository(self):
        repo = self.directory / "repo"
        repo.mkdir(mode=0o700)
        alias = self.directory / "alias"
        alias.symlink_to(repo, target_is_directory=True)
        with self.assertRaises(grant.Stop):
            grant.PrivateOutput(alias / "out", repo_root=repo)

    def test_no_partial_file_after_failure(self):
        output = grant.PrivateOutput(self.path)
        try:
            with patch.object(grant.os, "fsync", side_effect=OSError(SECRET)), self.assertRaises(grant.Stop) as caught:
                output.write({"VALUE": SECRET})
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertFalse(self.path.exists())
        finally:
            output.close()

    def test_secret_file_protected_and_one_line(self):
        for ending in (b"", b"\n", b"\r\n"):
            self.path.write_bytes(SECRET.encode() + ending)
            self.path.chmod(0o600)
            self.assertEqual(grant.read_client_secret(self.path), SECRET)
        for mode in (0o400, 0o600):
            self.path.chmod(mode)
            self.assertEqual(grant.read_client_secret(self.path), SECRET)
        for mode in (0o644, 0o660, 0o700):
            self.path.chmod(mode)
            with self.assertRaises(grant.Stop):
                grant.read_client_secret(self.path)
        self.path.chmod(0o600)
        for content in (b"", SECRET.encode() + b"\n\n", b"a\x00b", b"bad secret", b"x" * (grant.MAX_CREDENTIAL + 1)):
            self.path.write_bytes(content)
            with self.assertRaises(grant.Stop):
                grant.read_client_secret(self.path)

    def test_secret_file_symlink_hardlink_fifo_and_wrong_owner_refused(self):
        target = self.directory / "secret"
        target.write_text(SECRET)
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(grant.Stop):
            grant.read_client_secret(self.path)
        self.path.unlink()
        os.link(target, self.path)
        with self.assertRaises(grant.Stop):
            grant.read_client_secret(self.path)
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        with self.assertRaises(grant.Stop):
            grant.read_client_secret(self.path)
        self.path.unlink()
        with patch.object(grant.os, "getuid", return_value=os.getuid() + 1), self.assertRaises(grant.Stop):
            grant.read_client_secret(target)

    def test_hidden_prompt_fails_closed_on_echo_fallback(self):
        with patch.object(grant.sys.stdin, "isatty", return_value=False), self.assertRaises(grant.Stop):
            grant.read_client_secret()
        with patch.object(grant.sys.stdin, "isatty", return_value=True), patch.object(grant.getpass, "getpass", side_effect=grant.getpass.GetPassWarning(SECRET)), self.assertRaises(grant.Stop):
            grant.read_client_secret()
        with patch.object(grant.sys.stdin, "isatty", return_value=True), patch.object(grant.getpass, "getpass", return_value=SECRET):
            self.assertEqual(grant.read_client_secret(), SECRET)


class NetworkTests(unittest.TestCase):
    def response(self, raw=None, status=200, content_type="application/json", length=None):
        response = MagicMock()
        response.status = status
        response.getheader.side_effect = lambda name, default=None: {"Content-Type": content_type, "Content-Length": length}.get(name, default)
        response.read1.side_effect = [raw if raw is not None else json.dumps(token_response()).encode(), b""]
        return response

    def request(self, response):
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(grant.http.client, "HTTPSConnection", return_value=connection) as connection_type:
            result = grant.request_json("POST", "https://login.microsoftonline.com/consumers/oauth2/v2.0/token", b"synthetic", {})
        return result, connection, connection_type

    def test_tls_verifies_certificates_and_never_inherits_key_logging(self):
        with tempfile.TemporaryDirectory() as directory:
            keylog = Path(directory) / "tls-keys"
            with patch.dict(os.environ, {"SSLKEYLOGFILE": str(keylog)}):
                context = grant.tls_context()
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIsNone(context.keylog_filename)
            self.assertFalse(keylog.exists())

    def test_direct_tls_timeout_size_and_close(self):
        result, connection, factory = self.request(self.response())
        self.assertEqual(result["refresh_token"], REFRESH)
        self.assertEqual(factory.call_args.args, ("login.microsoftonline.com",))
        self.assertEqual(factory.call_args.kwargs["timeout"], grant.REQUEST_TIMEOUT)
        self.assertEqual(connection.request.call_args.args[:2], ("POST", "/consumers/oauth2/v2.0/token"))
        connection.close.assert_called_once()
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_redirect_error_html_and_response_size_fail_closed(self):
        for response in (self.response(status=302), self.response(status=307), self.response(status=400),
                         self.response(content_type="text/html"), self.response(length=str(grant.MAX_RESPONSE + 1)),
                         self.response(raw=b"x" * (grant.MAX_RESPONSE + 1)), self.response(raw=b"not-json"),
                         self.response(raw=b"[]"), self.response(raw=b'{"refresh_token":"a","refresh_token":"b"}')):
            with self.assertRaises(grant.Stop):
                self.request(response)

    def test_endpoint_overrides_credentials_in_urls_and_queries_refused(self):
        for url in ("http://login.microsoftonline.com/consumers/oauth2/v2.0/token",
                    "https://login.microsoftonline.com.evil.example/consumers/oauth2/v2.0/token",
                    "https://login.microsoftonline.com@evil.example/consumers/oauth2/v2.0/token",
                    "https://login.microsoftonline.com:443/consumers/oauth2/v2.0/token",
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token?secret=synthetic",
                    "https://login.microsoftonline.com/consumers/oauth2/v2.0/token#fragment",
                    "https://graph.microsoft.com/v1.0/me?redirect=evil", "https://graph.microsoft.com/beta/me"):
            with self.subTest(url=url), patch.object(grant.http.client, "HTTPSConnection") as connection, self.assertRaises(grant.Stop):
                grant.request_json("POST", url)
            connection.assert_not_called()

    def test_network_exceptions_are_sanitized(self):
        with patch.object(grant.http.client, "HTTPSConnection", side_effect=OSError(SECRET + ACCESS)), self.assertRaises(grant.Stop) as caught:
            grant.request_json("GET", grant.GRAPH_ME)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn(ACCESS, str(caught.exception))

    def test_hard_deadline_and_timer_cleanup(self):
        old_handler = signal.getsignal(signal.SIGALRM)
        with patch.object(grant, "REQUEST_TIMEOUT", 0.01):
            with self.assertRaises(grant.Stop):
                with grant.NetworkDeadline():
                    time.sleep(0.1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), old_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))


class CLITests(unittest.TestCase):
    def args(self, path):
        return ["--client-id", CLIENT, "--tenant-id", "consumers", "--mailbox", MAIL, "--output", str(path)]

    def test_argument_errors_never_echo_pasted_secrets(self):
        for args in (["--client-secret", SECRET], self.args("/synthetic/path"), ["--client-id", SECRET]):
            with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit):
                grant.main(args)
            self.assertNotIn(SECRET, stderr.getvalue())

    def test_success_new_instance_only_with_synthetic_transport(self):
        self.check_success(new=True)

    def test_success_regrant_preserves_existing_encryption_key(self):
        self.check_success(new=False)

    def check_success(self, new):
        with private_fixture() as directory:
            path = Path(directory) / "result.env"
            args = self.args(path)
            if new:
                args.append("--new-instance")
            else:
                key_file = Path(directory) / "key"
                key_file.write_text(KEY)
                key_file.chmod(0o600)
                args.extend(["--token-encryption-key-file", str(key_file)])
            class FakeCallback:
                def __init__(self, state):
                    self.state = state
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
                def wait_for_code(self):
                    return self.state.accept(callback(self.state))
            transport = SyntheticTransport()
            original_exchange = grant.exchange
            def synthetic_exchange(*args):
                return original_exchange(*args, transport=transport)
            with patch.object(grant, "read_client_secret", return_value=SECRET), patch.object(grant, "CallbackServer", FakeCallback), patch.object(grant, "exchange", synthetic_exchange), contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(grant.main(args), 0)
            all_output = stdout.getvalue() + stderr.getvalue()
            for secret in (SECRET, CODE, ACCESS, REFRESH, KEY, ACCOUNT):
                self.assertNotIn(secret, all_output)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            values = {line.split("=", 1)[0]: json.loads(line.split("=", 1)[1]) for line in path.read_text().splitlines() if line and not line.startswith("#")}
            self.assertEqual(values["MICROSOFT_REFRESH_TOKEN"], REFRESH)
            if new:
                self.assertRegex(values["MICROSOFT_TOKEN_ENCRYPTION_KEY"], r"^[0-9a-f]{64}$")
                self.assertNotEqual(values["MICROSOFT_TOKEN_ENCRYPTION_KEY"], KEY)
            else:
                self.assertEqual(values["MICROSOFT_TOKEN_ENCRYPTION_KEY"], KEY)

    def test_unexpected_exception_is_never_printed_and_creates_no_output(self):
        with private_fixture() as directory:
            path = Path(directory) / "result.env"
            with patch.object(grant, "read_client_secret", side_effect=RuntimeError(SECRET + REFRESH)), contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(grant.main(self.args(path) + ["--new-instance"]), 1)
            self.assertNotIn(SECRET, stdout.getvalue() + stderr.getvalue())
            self.assertNotIn(REFRESH, stdout.getvalue() + stderr.getvalue())
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
