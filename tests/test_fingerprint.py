import hashlib
import os
import shutil
import socket
import ssl
import subprocess
import unittest

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, StreamEnded
except ImportError:
    H2Connection = None


HOST = os.getenv("NGINX_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("NGINX_HTTP_PORT", "4433"))
STREAM_PORT = int(os.getenv("NGINX_STREAM_PORT", "4443"))
OPENSSL_BIN = os.getenv("OPENSSL_BIN")
CURL_BIN = os.getenv("CURL_BIN") or shutil.which("curl")

# FoxIO JA4 fixture: pcap/quic-tls-handshake.pcapng, client CRYPTO stream.
OFFICIAL_QUIC_CLIENT_HELLO = bytes.fromhex(
    "010001250303383d3bcc378f2dad654f7b937409876967b41befe42ba1acdebb"
    "8b9445787b84000006130113021303010000f6002d00020101001b0003020002"
    "446900050003026833000d001400120403080404010503080505010806060102"
    "01002b000302030400000013001100000e7777772e676f6f676c652e636f6d"
    "000a00080006001d0017001800390067040480f000000f000604806000000302"
    "45c0050480600000712702502480ff73db0c00000001aada0a7a000000010802"
    "40647128045256434d07048060000020048001000009024067d71be2ff92c99e"
    "fc060efac8e782f2800047520400000001010480007530001000050003026833"
    "003300260024001d00201dab42d2c5adfce8c137239e8de6b042bbd706b97af5"
    "dc7331dae4b80d1c5937"
)


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


def offered_alpn(client_hello):
    _, _, extensions = parse_client_hello(client_hello)
    extension_data = dict(extensions)
    data = extension_data.get(16, b"")
    if len(data) < 3 or int.from_bytes(data[:2]) != len(data) - 2:
        return ""

    protocols = []
    pos = 2
    while pos < len(data):
        length = data[pos]
        pos += 1
        if not length or pos + length > len(data):
            raise ValueError("invalid ALPN extension")
        protocol = data[pos : pos + length]
        protocols.append(
            "".join(
                chr(value)
                if 0x21 <= value <= 0x7E and value not in (ord("%"), ord(","))
                else f"%{value:02x}"
                for value in protocol
            )
        )
        pos += length

    return ",".join(protocols)


def fingerprints(client_hello, transport="t"):
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

    ja4_a = (
        f"{transport}{ja4_version}{'d' if 0 in extension_types else 'i'}"
        f"{min(len(clean_ciphers), 99):02d}"
        f"{min(len(clean_extensions), 99):02d}{alpn}"
    )
    ja4 = f"{ja4_a}_{cipher_hash}_{extension_hash}"
    ja4_r = f"{ja4_a}_{cipher_material}_{extension_material}"
    greased = any(
        is_grease(value)
        for value in ciphers + extension_types + groups
    )

    return (
        ja3,
        hashlib.md5(ja3.encode()).hexdigest(),
        ja4,
        ja4_r,
        str(int(greased)),
    )


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


def request_many_http2_settings():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])

    with socket.create_connection((HOST, HTTP_PORT), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=HOST) as connection:
            h2 = H2Connection(H2Configuration(client_side=True))
            h2.initiate_connection()
            preface = h2.data_to_send()

            # Track a second SETTINGS ACK in hyper-h2, but send 300 entries.
            h2.update_settings({0x10: 0})
            h2.data_to_send()
            payload = b"".join(
                (0x1000 + index).to_bytes(2, "big")
                + index.to_bytes(4, "big")
                for index in range(300)
            )
            settings_frame = (
                len(payload).to_bytes(3, "big")
                + b"\x04\x00\x00\x00\x00\x00"
                + payload
            )

            stream_id = h2.get_next_available_stream_id()
            h2.send_headers(
                stream_id,
                [
                    (":method", "GET"),
                    (":authority", f"{HOST}:{HTTP_PORT}"),
                    (":scheme", "https"),
                    (":path", "/"),
                ],
                end_stream=True,
            )
            connection.sendall(preface + settings_frame + h2.data_to_send())

            body = bytearray()
            complete = False
            while not complete:
                data = connection.recv(65535)
                if not data:
                    raise ConnectionError("HTTP/2 response ended early")
                for event in h2.receive_data(data):
                    if isinstance(event, DataReceived):
                        body.extend(event.data)
                        h2.acknowledge_received_data(
                            event.flow_controlled_length,
                            event.stream_id,
                        )
                    elif isinstance(event, StreamEnded):
                        complete = True
                pending = h2.data_to_send()
                if pending:
                    connection.sendall(pending)

    return body.decode()


class FingerprintTest(unittest.TestCase):
    def test_official_quic_ja4_fixture(self):
        _, _, ja4, ja4_r, _ = fingerprints(
            OFFICIAL_QUIC_CLIENT_HELLO, transport="q"
        )
        self.assertEqual(
            ja4,
            "q13d0310h3_55b375c5d22e_cd85d2d88918",
        )
        self.assertTrue(ja4_r.startswith("q13d0310h3_1301,1302,1303_"))

    def check_response(self, response, client_hello):
        values = dict(
            line.split(": ", 1)
            for line in response.replace("\r", "").splitlines()
            if ": " in line
        )
        ja3, ja3_hash, ja4, ja4_r, greased = fingerprints(client_hello)

        self.assertEqual(values["ja3"], ja3)
        self.assertEqual(values["ja3_hash"], ja3_hash)
        self.assertEqual(values["ja4"], ja4)
        self.assertEqual(values["ja4_r"], ja4_r)
        self.assertEqual(values["greased"], greased)
        self.assertEqual(values["alpn"], offered_alpn(client_hello))

    def test_http(self):
        self.check_response(*request(HTTP_PORT))

    def test_stream(self):
        self.check_response(*request(STREAM_PORT))

    def test_large_client_hello(self):
        protocols = ["http/1.1"] + [f"x{i:03d}" for i in range(80)]
        self.check_response(*request(HTTP_PORT, protocols))

    def test_non_alphanumeric_alpn_fallback(self):
        self.check_response(*request(HTTP_PORT, ["/foo", "http/1.1"]))

    def test_alpn_escaping(self):
        self.check_response(*request(HTTP_PORT, ["a,b", "x%y", "http/1.1"]))

    @unittest.skipUnless(CURL_BIN, "curl is not available")
    def test_http2_connection_prefix_cache(self):
        url = f"https://{HOST}:{HTTP_PORT}/"
        result = subprocess.run(
            [CURL_BIN, "-ksSf", "--http2", url, url],
            text=True,
            capture_output=True,
            timeout=10,
            check=True,
        )
        fingerprints = [
            line.split(": ", 1)[1]
            for line in result.stdout.splitlines()
            if line.startswith("h2fp: ")
        ]

        self.assertEqual(len(fingerprints), 2)
        self.assertTrue(all(fingerprints))
        for fingerprint in fingerprints:
            settings, window_update, priority, pseudo_headers = (
                fingerprint.split("|")
            )
            self.assertRegex(settings, r"^\d+:\d+(?:;\d+:\d+)*$")
            self.assertRegex(window_update, r"^\d+$")
            self.assertRegex(
                priority,
                r"^(?:0|\d+:[01]:\d+:\d+)$",
            )
            self.assertRegex(pseudo_headers, r"^[masp](?:,[masp]){3}$")
        self.assertEqual(
            fingerprints[0].split("|", 2)[:2],
            fingerprints[1].split("|", 2)[:2],
        )

    @unittest.skipUnless(H2Connection, "hyper-h2 is not installed")
    def test_many_http2_settings(self):
        response = request_many_http2_settings()
        values = dict(
            line.split(": ", 1)
            for line in response.splitlines()
            if ": " in line
        )
        settings = values["h2fp"].split("|", 1)[0]
        self.assertNotIn("TRUNCATED", settings)
        self.assertEqual(len(settings.split(";")), 307)
        self.assertRegex(settings, r"(?:^|;)4096:0(?:;|$)")
        self.assertRegex(settings, r"(?:^|;)4395:299(?:;|$)")

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
        raw_extensions = {
            int(value, 16)
            for value in values["ja4_r"].split("_", 3)[2].split(",")
        }
        self.assertTrue(set(extension_types) <= raw_extensions)


if __name__ == "__main__":
    unittest.main()
