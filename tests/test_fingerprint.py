import os
import socket
import ssl
import unittest


HOST = os.getenv("NGINX_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("NGINX_HTTP_PORT", "4433"))
STREAM_PORT = int(os.getenv("NGINX_STREAM_PORT", "4443"))


def request(port):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((HOST, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=HOST) as connection:
            connection.sendall(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            chunks = []
            while chunk := connection.recv(4096):
                chunks.append(chunk)

    return b"".join(chunks).decode()


class FingerprintTest(unittest.TestCase):
    def check_response(self, response):
        values = dict(
            line.split(": ", 1)
            for line in response.replace("\r", "").splitlines()
            if ": " in line
        )

        self.assertEqual(len(values["ja3"].split(",")), 5)
        self.assertRegex(values["ja3_hash"], r"^[0-9a-f]{32}$")
        self.assertRegex(
            values["ja4"],
            r"^[qt](?:1[0-3]|s3|00)[di][0-9]{4}[0-9A-Za-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$",
        )
        self.assertRegex(values["greased"], r"^[01]$")

    def test_http(self):
        self.check_response(request(HTTP_PORT))

    def test_stream(self):
        self.check_response(request(STREAM_PORT))


if __name__ == "__main__":
    unittest.main()
