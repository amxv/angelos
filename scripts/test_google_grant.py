"""Synthetic fixtures only. Never contacts Google or uses real credentials."""
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

import google_grant as grant

CLIENT = "1234567890-synthetic.apps.googleusercontent.com"
SECRET = "synthetic-client-secret"
CODE = "synthetic-code"
ACCESS = "synthetic-access-token"
REFRESH = "synthetic-refresh-token"
MAIL = "person@example.test"


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
    return grant.PendingGrant(CLIENT, clock=clock)


def callback(grant_state, **extra):
    return urllib.parse.urlencode({"code": CODE, "state": grant_state.state, **extra}).encode()


def accepted():
    state = pending()
    code = state.accept(callback(state))
    return state, code


def token_response(**changes):
    return {"access_token": ACCESS, "refresh_token": REFRESH, "token_type": "Bearer",
            "scope": "https://mail.google.com/", **changes}


class SyntheticTransport:
    def __init__(self, tokens=None, identity=None):
        self.calls = []
        self.tokens = token_response() if tokens is None else tokens
        self.identity = {"emailAddress": MAIL} if identity is None else identity

    def __call__(self, method, url, data=None, headers=None):
        self.calls.append((method, url, data, headers))
        return self.tokens if method == "POST" else self.identity


class GrantTests(unittest.TestCase):
    def test_authorization_url_is_pinned_pkce_and_only_full_mail(self):
        state = pending()
        url = urllib.parse.urlsplit(state.authorization_url())
        self.assertEqual((url.scheme, url.netloc, url.path),
                         ("https", "accounts.google.com", "/o/oauth2/v2/auth"))
        fields = urllib.parse.parse_qs(url.query)
        self.assertEqual(fields["redirect_uri"], ["http://127.0.0.1:8401/callback"])
        self.assertEqual(fields["response_type"], ["code"])
        self.assertEqual(fields["scope"], ["https://mail.google.com/"])
        self.assertEqual(fields["access_type"], ["offline"])
        self.assertEqual(fields["include_granted_scopes"], ["false"])
        self.assertEqual(fields["prompt"], ["consent select_account"])
        self.assertEqual(fields["code_challenge_method"], ["S256"])
        expected = base64.urlsafe_b64encode(hashlib.sha256(state.verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(fields["code_challenge"], [expected])
        for name in ("client_secret", "code", "code_verifier", "login_hint", "access_token", "refresh_token", "response_mode"):
            self.assertNotIn(name, fields)
        self.assertGreaterEqual(len(state.state), 43)
        self.assertTrue(43 <= len(state.verifier) <= 128)
        other = pending()
        self.assertNotEqual(state.state, other.state)
        self.assertNotEqual(state.verifier, other.verifier)

    def test_only_google_client_identifier(self):
        self.assertEqual(grant.identifier(CLIENT), CLIENT)
        for client in (None, "", SECRET, CLIENT + "\n", CLIENT + ".evil.example", "../" + CLIENT, "https://" + CLIENT,
                       "x" * 256 + ".apps.googleusercontent.com", CLIENT + "?secret=x"):
            with self.subTest(client=client), self.assertRaises(grant.Stop):
                grant.identifier(client)

    def test_success_and_single_use_state(self):
        state = pending()
        self.assertEqual(state.accept(callback(state)), CODE)
        self.assertTrue(state.consumed)
        with self.assertRaises(grant.CallbackRejected):
            state.accept(callback(state))

    def test_wrong_missing_duplicate_malformed_state_does_not_consume(self):
        state = pending()
        for data in (b"code=synthetic", callback(state, state="incorrect"), callback(state) + b"&state=duplicate",
                     b"state=%ff&code=synthetic", b"state=%ZZ&code=synthetic", b"broken", b"x=1&" * 20,
                     b"x" * (grant.MAX_CALLBACK_QUERY + 1)):
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
        with self.assertRaises(grant.Stop) as caught:
            state.accept(callback(state, error="access_denied", error_description=SECRET + ACCESS))
        self.assertTrue(state.consumed)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn(ACCESS, str(caught.exception))

    def test_matched_state_invalid_code_is_consumed(self):
        for code in ("", "bad\ncode", "bad code", "x" * (grant.MAX_CREDENTIAL + 1)):
            state = pending()
            # The oversized query is rejected without consumption before parsing.
            data = callback(state, code=code)
            with self.assertRaises(grant.CallbackRejected):
                state.accept(data)
            self.assertEqual(state.consumed, len(data) <= grant.MAX_CALLBACK_QUERY)

    def test_exchange_uses_form_body_and_verifies_gmail_profile(self):
        state, code = accepted()
        transport = SyntheticTransport(identity={"emailAddress": "Person@example.test"})
        values = grant.exchange(state, code, SECRET, MAIL, transport)
        method, url, data, headers = transport.calls[0]
        self.assertEqual((method, url), ("POST", "https://oauth2.googleapis.com/token"))
        body = urllib.parse.parse_qs(data.decode())
        self.assertEqual(body, {"client_id": [CLIENT], "client_secret": [SECRET], "code": [CODE],
                               "code_verifier": [state.verifier], "redirect_uri": [grant.REDIRECT_URI],
                               "grant_type": ["authorization_code"]})
        self.assertEqual(transport.calls[1], ("GET", grant.GMAIL_PROFILE, None,
                                            {"Authorization": "Bearer " + ACCESS, "Accept": "application/json"}))
        self.assertEqual(values, {"MAIL_PROVIDER": "gmail", "MAIL_AUTH_MODE": "google_oauth2",
                                  "MAIL_USERNAME": "Person@example.test", "MAIL_FROM": "Person@example.test",
                                  "GOOGLE_CLIENT_ID": CLIENT, "GOOGLE_CLIENT_SECRET": SECRET,
                                  "GOOGLE_REFRESH_TOKEN": REFRESH})
        for _, request_url, _, _ in transport.calls:
            for secret in (SECRET, CODE, ACCESS, REFRESH, state.verifier):
                self.assertNotIn(secret, request_url)

    def test_exchange_at_most_once(self):
        state, code = accepted()
        transport = SyntheticTransport()
        grant.exchange(state, code, SECRET, MAIL, transport)
        with self.assertRaises(grant.Stop):
            grant.exchange(state, code, SECRET, MAIL, transport)
        self.assertEqual(len(transport.calls), 2)

    def test_exchange_failed_attempt_is_not_retried(self):
        state, code = accepted()
        transport = SyntheticTransport(tokens={})
        with self.assertRaises(grant.Stop):
            grant.exchange(state, code, SECRET, MAIL, transport)
        with self.assertRaises(grant.Stop):
            grant.exchange(state, code, SECRET, MAIL, transport)
        self.assertEqual(len(transport.calls), 1)

    def test_exchange_rejects_missing_expired_state_and_bad_mailbox_before_network(self):
        for state, mailbox in ((pending(), MAIL), (accepted()[0], "bad\n@example.test")):
            transport = SyntheticTransport()
            with self.assertRaises(grant.Stop):
                grant.exchange(state, CODE, SECRET, mailbox, transport)
            self.assertEqual(transport.calls, [])
        state, code = accepted()
        state.deadline = 99
        transport = SyntheticTransport()
        with self.assertRaises(grant.Stop):
            grant.exchange(state, code, SECRET, MAIL, transport)
        self.assertEqual(transport.calls, [])

    def test_required_tokens_and_exact_scope_fail_closed_before_identity_lookup(self):
        responses = [token_response(**change) for change in (
            {"access_token": None}, {"access_token": "bad\r\nheader"}, {"refresh_token": ""},
            {"token_type": "MAC"}, {"token_type": []}, {"scope": "https://www.googleapis.com/auth/gmail.modify"},
            {"scope": ["https://mail.google.com/"]}, {"scope": "https://MAIL.google.com/"},
            {"scope": "https://mail.google.com"}, {"scope": "https://mail.google.com/ openid"},
            {"scope": "https://mail.google.com/\n"}, {"scope": None})]
        absent = token_response()
        del absent["scope"]
        for tokens in responses + [absent]:
            state, code = accepted()
            transport = SyntheticTransport(tokens=tokens)
            with self.subTest(tokens=tokens), self.assertRaises(grant.Stop):
                grant.exchange(state, code, SECRET, MAIL, transport)
            self.assertEqual(len(transport.calls), 1)

    def test_callback_scope_is_not_authoritative(self):
        state = pending()
        code = state.accept(callback(state, scope="https://mail.google.com/"))
        with self.assertRaises(grant.Stop):
            grant.exchange(state, code, SECRET, MAIL, SyntheticTransport(tokens=token_response(scope="openid")))
        state = pending()
        code = state.accept(callback(state, scope="untrusted"))
        grant.exchange(state, code, SECRET, MAIL, SyntheticTransport())

    def test_identity_requires_primary_gmail_address_and_expected_account(self):
        for identity in ({"emailAddress": None}, {}, {"email": MAIL}, {"emailAddress": "wrong@example.test"},
                         {"emailAddress": "Name <person@example.test>"}, {"emailAddress": "bad\n@example.test"},
                         {"emailAddress": "a" * 255 + "@example.test"}, []):
            with self.subTest(identity=identity), self.assertRaises(grant.Stop):
                state, code = accepted()
                grant.exchange(state, code, SECRET, MAIL, SyntheticTransport(identity=identity))


class SocketFixtures(unittest.TestCase):
    def wire(self, query, **headers):
        merged = {"Host": "127.0.0.1:8401", **headers}
        return (b"GET /callback?" + query + b" HTTP/1.1\r\n" +
                "\r\n".join(k + ": " + v for k, v in merged.items()).encode() + b"\r\n\r\n")

    def parse(self, wire):
        server, client = socket.socketpair()
        try:
            client.sendall(wire)
            client.shutdown(socket.SHUT_WR)
            return grant.read_callback(server, time.monotonic() + 2)
        finally:
            client.close()
            server.close()

    def test_local_callback_parser(self):
        query = callback(pending())
        self.assertEqual(self.parse(self.wire(query)), query)
        self.assertEqual(self.parse(self.wire(query, **{"Content-Length": "0"})), query)

    def test_callback_rejects_host_path_method_body_fragment_and_duplicate_headers(self):
        original = self.wire(b"code=synthetic&state=x")
        fixtures = [original.replace(b"GET ", b"POST "),
                    original.replace(b"/callback?", b"http://127.0.0.1:8401/callback?"),
                    original.replace(b"/callback?", b"/other?"),
                    original.replace(b"/callback?", b"/callback/?"),
                    original.replace(b"state=x", b"state=x#fragment"),
                    original.replace(b"127.0.0.1:8401", b"evil.example:8401"),
                    original.replace(b"127.0.0.1:8401", b"localhost:8401"),
                    original.replace(b"Host:", b" Host:"),
                    original.replace(b"Host:", b"HOST: bad\r\nHost:"),
                    original.replace(b"Host:", b"Transfer-Encoding: chunked\r\nHost:"),
                    original.replace(b"Host:", b"Content-Length: 1\r\nHost:"),
                    original.replace(b"Host:", b"Content-Length: 0\r\nContent-Length: 0\r\nHost:"),
                    original.replace(b"Host:", b"X-Bad: control\x00value\r\nHost:"), original + b"extra"]
        for wire in fixtures:
            with self.subTest(wire=wire[:60]), self.assertRaises(grant.CallbackRejected):
                self.parse(wire)

    def test_oversized_headers_query_and_invalid_request(self):
        for wire in (b"GET /callback?x HTTP/1.1\r\nX: " + b"x" * (grant.MAX_HEADERS + 5000),
                     self.wire(b"x" * (grant.MAX_CALLBACK_QUERY + 1)),
                     b"GET /callback HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n\r\n",
                     b"GET /callback? HTTP/1.1\r\nHost: 127.0.0.1:8401\r\n\r\n",
                     self.wire(b"x", **{"Content-Length": "-1"}), self.wire(b"x", **{"Content-Length": "100"})):
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
        with patch.object(grant.socketserver.TCPServer, "__init__", return_value=None) as bind:
            grant.CallbackServer(pending())
        self.assertEqual(bind.call_args.args[0], ("127.0.0.1", 8401))
        with patch.object(grant.socketserver.TCPServer, "__init__", side_effect=OSError(SECRET)), self.assertRaises(grant.Stop) as caught:
            grant.CallbackServer(pending())
        self.assertNotIn(SECRET, str(caught.exception))

    def test_callback_handler_never_reflects_or_logs_secrets(self):
        state = pending(clock=time.monotonic)
        server = MagicMock(grant=state, code=None, failure=None)
        left, right = socket.socketpair()
        try:
            right.sendall(self.wire(callback(state)))
            with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                grant.CallbackHandler(left, ("127.0.0.1", 1), server)
            response = right.recv(4096).decode()
            self.assertTrue(response.startswith("HTTP/1.1 200"))
            for secret in (CODE, SECRET, state.state):
                self.assertNotIn(secret, response + stdout.getvalue() + stderr.getvalue())
            self.assertIn("Cache-Control: no-store", response)
            self.assertIn("Referrer-Policy: no-referrer", response)
            self.assertIn("Content-Security-Policy: default-src 'none'", response)
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
            result = grant.request_json("POST", "https://oauth2.googleapis.com/token", b"synthetic", {})
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
        self.assertEqual(factory.call_args.args, ("oauth2.googleapis.com",))
        self.assertEqual(factory.call_args.kwargs["timeout"], grant.REQUEST_TIMEOUT)
        self.assertEqual(connection.request.call_args.args[:2], ("POST", "/token"))
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
        for url in ("http://oauth2.googleapis.com/token",
                    "https://oauth2.googleapis.com.evil.example/token",
                    "https://oauth2.googleapis.com@evil.example/token",
                    "https://oauth2.googleapis.com:443/token",
                    "https://oauth2.googleapis.com/common/oauth2/v2.0/token",
                    "https://oauth2.googleapis.com/token?secret=synthetic",
                    "https://oauth2.googleapis.com/token#fragment",
                    "https://gmail.googleapis.com/v1.0/me?redirect=evil", "https://gmail.googleapis.com/beta/me"):
            with self.subTest(url=url), patch.object(grant.http.client, "HTTPSConnection") as connection, self.assertRaises(grant.Stop):
                grant.request_json("POST", url)
            connection.assert_not_called()

    def test_network_exceptions_are_sanitized(self):
        with patch.object(grant.http.client, "HTTPSConnection", side_effect=OSError(SECRET + ACCESS)), self.assertRaises(grant.Stop) as caught:
            grant.request_json("GET", grant.GMAIL_PROFILE)
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

    def test_profile_failure_is_actionable_without_reading_error_body(self):
        response = self.response(status=403, raw=(SECRET + ACCESS).encode())
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch.object(grant.http.client, "HTTPSConnection", return_value=connection), self.assertRaises(grant.Stop) as caught:
            grant.request_json("GET", grant.GMAIL_PROFILE)
        self.assertIn("enable the Gmail API", str(caught.exception))
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn(ACCESS, str(caught.exception))
        response.read1.assert_not_called()
        connection.close.assert_called_once()

    def test_proxy_environment_does_not_change_direct_destination(self):
        proxies = {key: "http://proxy.invalid:8765" for key in
                   ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}
        with patch.dict(os.environ, proxies):
            _, connection, factory = self.request(self.response())
        self.assertEqual(factory.call_args.args, ("oauth2.googleapis.com",))
        connection.set_tunnel.assert_not_called()

    def test_wrong_methods_are_refused_before_network(self):
        for method, url in (("GET", grant.TOKEN_ENDPOINT), ("POST", grant.GMAIL_PROFILE),
                            ("POST", grant.AUTHORIZATION_ENDPOINT)):
            with patch.object(grant.http.client, "HTTPSConnection") as connection, self.assertRaises(grant.Stop):
                grant.request_json(method, url)
            connection.assert_not_called()

    def test_existing_alarm_is_not_replaced(self):
        with patch.object(grant.signal, "getitimer", return_value=(4.0, 0.0)), patch.object(grant.signal, "setitimer") as timer, self.assertRaises(grant.Stop):
            with grant.NetworkDeadline():
                self.fail("An existing timer must fail closed")
        timer.assert_not_called()


class CLITests(unittest.TestCase):
    def args(self, path):
        return ["--client-id", CLIENT, "--mailbox", MAIL, "--output", str(path)]

    def test_argument_errors_never_echo_pasted_secrets(self):
        for args in (["--client-secret", SECRET], ["--client-id", SECRET],
                     self.args("/synthetic/path") + ["--unknown", SECRET]):
            with contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit):
                grant.main(args)
            self.assertNotIn(SECRET, stderr.getvalue())

    def test_success_only_with_synthetic_transport_and_private_output(self):
        with private_fixture() as directory:
            path = Path(directory) / "result.env"
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
                self.assertEqual(grant.main(self.args(path)), 0)
            all_output = stdout.getvalue() + stderr.getvalue()
            for secret in (SECRET, CODE, ACCESS, REFRESH):
                self.assertNotIn(secret, all_output)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            values = {line.split("=", 1)[0]: json.loads(line.split("=", 1)[1]) for line in path.read_text().splitlines() if line and not line.startswith("#")}
            self.assertEqual(values["GOOGLE_REFRESH_TOKEN"], REFRESH)
            self.assertEqual(set(values), {"MAIL_PROVIDER", "MAIL_AUTH_MODE", "MAIL_USERNAME", "MAIL_FROM", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN"})

    def test_unexpected_exception_is_never_printed_and_creates_no_output(self):
        with private_fixture() as directory:
            path = Path(directory) / "result.env"
            with patch.object(grant, "read_client_secret", side_effect=RuntimeError(SECRET + REFRESH)), contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(grant.main(self.args(path)), 1)
            self.assertFalse(path.exists())
            self.assertNotIn(SECRET, stdout.getvalue() + stderr.getvalue())
            self.assertNotIn(REFRESH, stdout.getvalue() + stderr.getvalue())

    def test_existing_output_stops_before_secret_entry_or_network(self):
        with private_fixture() as directory:
            path = Path(directory) / "result.env"
            path.write_text("keep existing settings")
            with patch.object(grant, "read_client_secret") as secret, patch.object(grant, "CallbackServer") as listener, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(grant.main(self.args(path)), 1)
            secret.assert_not_called()
            listener.assert_not_called()
            self.assertEqual(path.read_text(), "keep existing settings")


if __name__ == "__main__":
    unittest.main()
