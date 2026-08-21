import hashlib
import os
import socket
import ssl
import subprocess
import unittest


HOST = os.getenv("NGINX_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("NGINX_HTTP_PORT", "4433"))
STREAM_PORT = int(os.getenv("NGINX_STREAM_PORT", "4443"))
OPENSSL_BIN = os.getenv("OPENSSL_BIN")


def is_grease(value):
    return value & 0x0F0F == 0x0A0A and value & 0xFF == value >> 8


def uint16s(data):
    if len(data) % 2:
        raise ValueError("odd uint16 vector")
    return [int.from_bytes(data[i : i + 2]) for i in range(0, len(data), 2)]


def parse_client_hello(data):
    if data[0] != 1 or int.from_bytes(data[1:4]) != len(data) - 4:
        raise ValueError("invalid ClientHello")

    pos = 4
    version = int.from_bytes(data[pos : pos + 2])
    pos += 2 + 32
    pos += 1 + data[pos]

    length = int.from_bytes(data[pos : pos + 2])
    pos += 2
    ciphers = uint16s(data[pos : pos + length])
    pos += length
    pos += 1 + data[pos]

    length = int.from_bytes(data[pos : pos + 2])
    pos += 2
    end = pos + length
    extensions = []
    while pos < end:
        ext_type = int.from_bytes(data[pos : pos + 2])
        ext_len = int.from_bytes(data[pos + 2 : pos + 4])
        pos += 4
        extensions.append((ext_type, data[pos : pos + ext_len]))
        pos += ext_len
    if pos != end:
        raise ValueError("invalid extensions")

    return version, ciphers, extensions


def fingerprints(client_hello):
    version, ciphers, extensions = parse_client_hello(client_hello)
    extension_types = [ext_type for ext_type, _ in extensions]
    extension_data = dict(extensions)

    clean_ciphers = [value for value in ciphers if not is_grease(value)]
    clean_extensions = [
        value for value in extension_types if not is_grease(value)
    ]

    groups = []
    if 10 in extension_data and len(extension_data[10]) >= 2:
        length = int.from_bytes(extension_data[10][:2])
        groups = uint16s(extension_data[10][2 : 2 + length])
    clean_groups = [value for value in groups if not is_grease(value)]

    formats = []
    if 11 in extension_data and extension_data[11]:
        length = extension_data[11][0]
        formats = list(extension_data[11][1 : 1 + length])

    ja3 = ",".join(
        [
            str(version),
            "-".join(map(str, clean_ciphers)),
            "-".join(map(str, clean_extensions)),
            "-".join(map(str, clean_groups)),
            "-".join(map(str, formats)),
        ]
    )

    supported = []
    if 43 in extension_data and extension_data[43]:
        length = extension_data[43][0]
        supported = uint16s(extension_data[43][1 : 1 + length])
        supported = [value for value in supported if not is_grease(value)]
    ja4_version = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
    }.get(max(supported) if supported else version, "00")

    alpn = "00"
    if 16 in extension_data and len(extension_data[16]) >= 4:
        first_len = extension_data[16][2]
        if first_len and first_len <= len(extension_data[16]) - 3:
            first = extension_data[16][3]
            last = extension_data[16][first_len + 2]
            if (
                chr(first).isascii()
                and chr(first).isalnum()
                and chr(last).isascii()
                and chr(last).isalnum()
            ):
                alpn = chr(first) + chr(last)
            else:
                alpn = f"{first:02x}"[0] + f"{last:02x}"[-1]

    cipher_material = ",".join(f"{value:04x}" for value in sorted(clean_ciphers))
    cipher_hash = (
        hashlib.sha256(cipher_material.encode()).hexdigest()[:12]
        if cipher_material
        else "0" * 12
    )

    hashed_extensions = sorted(
        value for value in clean_extensions if value not in (0, 16)
    )
    extension_material = ",".join(
        f"{value:04x}" for value in hashed_extensions
    )
    if 13 in extension_data and len(extension_data[13]) >= 2:
        length = int.from_bytes(extension_data[13][:2])
        sigalgs = uint16s(extension_data[13][2 : 2 + length])
        sigalgs = [value for value in sigalgs if not is_grease(value)]
        if sigalgs:
            extension_material += "_" + ",".join(
                f"{value:04x}" for value in sigalgs
            )
    extension_hash = (
        hashlib.sha256(extension_material.encode()).hexdigest()[:12]
        if extension_material
        else "0" * 12
    )

    ja4 = (
        f"t{ja4_version}{'d' if 0 in extension_types else 'i'}"
        f"{min(len(clean_ciphers), 99):02d}"
        f"{min(len(clean_extensions), 99):02d}{alpn}"
        f"_{cipher_hash}_{extension_hash}"
    )
    greased = any(
        is_grease(value)
        for value in ciphers + extension_types + groups
    )

    return ja3, hashlib.md5(ja3.encode()).hexdigest(), ja4, str(int(greased))


def request(port, alpn_protocols=None):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if alpn_protocols:
        context.set_alpn_protocols(alpn_protocols)

    client_hellos = []

    def capture(_connection, direction, _version, _content_type,
                message_type, data):
        if (
            direction == "write"
            and getattr(message_type, "name", "") == "CLIENT_HELLO"
        ):
            client_hellos.append(bytes(data))

    context._msg_callback = capture

    with socket.create_connection((HOST, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=HOST) as connection:
            connection.sendall(
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            chunks = []
            while chunk := connection.recv(4096):
                chunks.append(chunk)

    if len(client_hellos) != 1:
        raise RuntimeError("ClientHello capture failed")
    return b"".join(chunks).decode(), client_hellos[0]


class FingerprintTest(unittest.TestCase):
    def check_response(self, response, client_hello):
        values = dict(
            line.split(": ", 1)
            for line in response.replace("\r", "").splitlines()
            if ": " in line
        )
        ja3, ja3_hash, ja4, greased = fingerprints(client_hello)

        self.assertEqual(values["ja3"], ja3)
        self.assertEqual(values["ja3_hash"], ja3_hash)
        self.assertEqual(values["ja4"], ja4)
        self.assertEqual(values["greased"], greased)

    def test_http(self):
        self.check_response(*request(HTTP_PORT))

    def test_stream(self):
        self.check_response(*request(STREAM_PORT))

    def test_large_client_hello(self):
        protocols = ["http/1.1"] + [f"x{i:03d}" for i in range(80)]
        self.check_response(*request(HTTP_PORT, protocols))

    def test_non_alphanumeric_alpn_fallback(self):
        self.check_response(*request(HTTP_PORT, ["/foo", "http/1.1"]))

    @unittest.skipUnless(OPENSSL_BIN, "OPENSSL_BIN is not set")
    def test_many_unknown_extensions(self):
        extension_types = list(range(1000, 1100))
        result = subprocess.run(
            [
                OPENSSL_BIN,
                "s_client",
                "-quiet",
                "-connect",
                f"{HOST}:{HTTP_PORT}",
                "-serverinfo",
                ",".join(map(str, extension_types)),
            ],
            input="GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            text=True,
            capture_output=True,
            timeout=10,
            check=True,
        )
        values = dict(
            line.split(": ", 1)
            for line in result.stdout.replace("\r", "").splitlines()
            if ": " in line
        )
        extensions = list(map(int, values["ja3"].split(",")[2].split("-")))

        self.assertEqual(extensions[: len(extension_types)], extension_types)
        self.assertEqual(
            hashlib.md5(values["ja3"].encode()).hexdigest(),
            values["ja3_hash"],
        )
        self.assertEqual(values["ja4"][6:8], "99")
        self.assertEqual(len(values["ja4"]), 36)


if __name__ == "__main__":
    unittest.main()
