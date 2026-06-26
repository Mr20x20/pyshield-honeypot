"""
honeypot.py — PyShield Honeypot
Fake SSH and HTTP servers that log attacker activity.

SSH server:  listens on SSH_PORT (2222)
             completes real SSH handshake via paramiko
             always rejects login — but logs every credential attempt

HTTP server: listens on HTTP_PORT (8080)
             returns fake admin panel responses
             logs every path, method, and user-agent
"""

import logging
import socket
import threading
import sys
from datetime import datetime

import paramiko

# Suppress paramiko's own noisy logging
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

import database as db
from config import (
    SSH_HOST, SSH_PORT, SSH_BANNER, SSH_HOST_KEY,
    SSH_AUTH_ALWAYS_FAIL, SSH_LINGER_SECONDS,
    HTTP_HOST, HTTP_PORT, HTTP_SERVER_HEADER,
)

logger = logging.getLogger("honeypot")


# ── SSH Honeypot ───────────────────────────────────────────────────────────────

def _generate_host_key() -> paramiko.RSAKey:
    """
    Load or generate the RSA host key for the fake SSH server.
    Paramiko needs this to complete the SSH handshake.
    Real SSH servers have a persistent host key — we do the same
    so returning attackers see the same fingerprint each time.
    """
    if SSH_HOST_KEY.exists():
        logger.info("Loading existing SSH host key from %s", SSH_HOST_KEY)
        return paramiko.RSAKey(filename=str(SSH_HOST_KEY))

    logger.info("Generating new SSH host key...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(SSH_HOST_KEY))
    logger.info("SSH host key saved to %s", SSH_HOST_KEY)
    return key


class HoneypotSSHInterface(paramiko.ServerInterface):
    """
    Implements paramiko's ServerInterface — defines how our fake SSH
    server responds to authentication attempts.

    Key concept: paramiko handles the low-level SSH protocol (key exchange,
    encryption, handshake). We only need to implement the auth callbacks.
    """

    def __init__(self, client_ip: str, client_port: int):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.username    = None

    def check_channel_request(self, kind, chanid):
        # Accept channel requests — needed to keep connection alive
        # long enough for the attacker to try more passwords
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Called every time an attacker tries username + password.
        We log it, then always return AUTH_FAILED.
        """
        logger.info(
            "SSH attempt: %s:%d tried user='%s' pass='%s'",
            self.client_ip, self.client_port, username, password
        )
        db.log_ssh_attempt(self.client_ip, self.client_port, username, password)
        self.username = username

        # AUTH_FAILED tells paramiko to reject the login
        # The attacker's tool will then try another password
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key) -> int:
        """Reject public key auth too — we only want password attempts."""
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        """Tell the client only password auth is supported."""
        return "password"


def _handle_ssh_client(client_socket: socket.socket,
                       client_addr: tuple,
                       host_key: paramiko.RSAKey) -> None:
    """
    Handle one incoming SSH connection in its own thread.
    Sets up paramiko transport, runs the fake server interface.
    """
    ip, port = client_addr
    transport = None

    try:
        # Wrap raw socket in paramiko Transport
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER   # fake version string
        transport.add_server_key(host_key)

        server_interface = HoneypotSSHInterface(ip, port)

        # Start SSH negotiation — this blocks until handshake completes
        # or the client disconnects
        transport.start_server(server=server_interface)

        # Wait briefly — gives attacker time to try more passwords
        # before we close the connection
        import time
        time.sleep(SSH_LINGER_SECONDS)

    except paramiko.SSHException as e:
        logger.debug("SSH negotiation failed from %s: %s", ip, e)
    except EOFError:
        logger.debug("SSH client %s disconnected early", ip)
    except Exception as e:
        logger.debug("SSH handler error for %s: %s", ip, e)
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_socket.close()
        except Exception:
            pass


def start_ssh_server() -> None:
    """
    Start the fake SSH server.
    Runs forever, accepting connections and spawning a handler thread
    for each one so multiple attackers can connect simultaneously.
    """
    host_key = _generate_host_key()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((SSH_HOST, SSH_PORT))
    except PermissionError:
        logger.error(
            "Cannot bind SSH honeypot to port %d — "
            "try a port above 1024 or run as admin", SSH_PORT
        )
        return
    except OSError as e:
        logger.error("SSH bind failed: %s", e)
        return

    server_socket.listen(10)
    logger.info("SSH honeypot listening on %s:%d", SSH_HOST, SSH_PORT)

    while True:
        try:
            client_sock, client_addr = server_socket.accept()
            logger.info("SSH connection from %s:%d", *client_addr)

            t = threading.Thread(
                target=_handle_ssh_client,
                args=(client_sock, client_addr, host_key),
                daemon=True,
            )
            t.start()

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error("SSH accept error: %s", e)


# ── HTTP Honeypot ──────────────────────────────────────────────────────────────

# Fake admin panel HTML — looks like a real login page
# Attackers probing for admin panels will see this and try credentials
_FAKE_LOGIN_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
<h2>Administrator Login</h2>
<form method="POST">
  <label>Username: <input type="text" name="username"></label><br>
  <label>Password: <input type="password" name="password"></label><br>
  <input type="submit" value="Login">
</form>
</body>
</html>
"""

_FAKE_401 = """\
<!DOCTYPE html>
<html>
<head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1><p>Authentication required.</p></body>
</html>
"""


def _parse_http_request(raw: bytes) -> tuple[str, str, str]:
    """
    Parse raw HTTP request bytes into (method, path, user_agent).
    We don't need a full HTTP parser — just the first line and headers.
    """
    try:
        text    = raw.decode("utf-8", errors="replace")
        lines   = text.split("\r\n")
        parts   = lines[0].split(" ")
        method  = parts[0] if len(parts) > 0 else "UNKNOWN"
        path    = parts[1] if len(parts) > 1 else "/"

        user_agent = ""
        for line in lines[1:]:
            if line.lower().startswith("user-agent:"):
                user_agent = line.split(":", 1)[1].strip()
                break

        return method, path, user_agent
    except Exception:
        return "UNKNOWN", "/", ""


def _build_http_response(method: str, path: str) -> bytes:
    """
    Return a fake but realistic HTTP response.
    / and /admin → fake login page (200)
    everything else → 401 Unauthorized
    This makes the honeypot look like a real admin panel to scanners.
    """
    if path in ["/", "/admin", "/admin/", "/login", "/login/"]:
        body    = _FAKE_LOGIN_PAGE.encode()
        status  = "200 OK"
        ctype   = "text/html"
    else:
        body    = _FAKE_401.encode()
        status  = "401 Unauthorized"
        ctype   = "text/html"

    now = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    headers = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: {HTTP_SERVER_HEADER}\r\n"
        f"Date: {now}\r\n"
        f"Content-Type: {ctype}; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return headers.encode() + body


def _handle_http_client(client_socket: socket.socket,
                        client_addr: tuple) -> None:
    """Handle one HTTP connection — read request, log it, send fake response."""
    ip, port = client_addr

    try:
        client_socket.settimeout(5)
        raw = b""

        # Read until we have the full HTTP headers
        while b"\r\n\r\n" not in raw:
            chunk = client_socket.recv(1024)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 8192:   # prevent memory abuse
                break

        if not raw:
            return

        method, path, user_agent = _parse_http_request(raw)

        logger.info(
            "HTTP request: %s:%d %s %s (UA: %s)",
            ip, port, method, path, user_agent[:60] if user_agent else "none"
        )

        db.log_http_request(ip, port, method, path, user_agent)

        response = _build_http_response(method, path)
        client_socket.sendall(response)

    except socket.timeout:
        pass
    except Exception as e:
        logger.debug("HTTP handler error for %s: %s", ip, e)
    finally:
        try:
            client_socket.close()
        except Exception:
            pass


def start_http_server() -> None:
    """
    Start the fake HTTP server.
    Same pattern as SSH — accept loop + per-connection thread.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((HTTP_HOST, HTTP_PORT))
    except PermissionError:
        logger.error(
            "Cannot bind HTTP honeypot to port %d — "
            "try a port above 1024 or run as admin", HTTP_PORT
        )
        return
    except OSError as e:
        logger.error("HTTP bind failed: %s", e)
        return

    server_socket.listen(10)
    logger.info("HTTP honeypot listening on %s:%d", HTTP_HOST, HTTP_PORT)

    while True:
        try:
            client_sock, client_addr = server_socket.accept()
            logger.info("HTTP connection from %s:%d", *client_addr)

            t = threading.Thread(
                target=_handle_http_client,
                args=(client_sock, client_addr),
                daemon=True,
            )
            t.start()

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error("HTTP accept error: %s", e)
