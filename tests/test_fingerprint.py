import datetime
import hashlib
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from decimal import Decimal, ROUND_HALF_UP

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, StreamEnded
except ImportError:
    H2Connection = None


HOST = os.getenv("NGINX_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("NGINX_HTTP_PORT", "4433"))
HTTP_PLAIN_PORT = int(os.getenv("NGINX_HTTP_PLAIN_PORT", "4435"))
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


def request(port, alpn_protocols=None, http_request=None, context=None):
    if context is None:
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
                http_request or
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
                priority_weight=256,
                priority_depends_on=3,
                priority_exclusive=True,
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


def send_kernel_dropped_packets(port, stop):
    # Anyone can send these to the port; JA4L must ignore them, not discard flows.
    def ip(fragment, payload):
        return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, fragment,
                           64, socket.IPPROTO_UDP, 0, b"\x7f\0\0\1", b"\x7f\0\0\1") + payload
    fragment = ip(1, struct.pack("!HHHH", port, port, 8, 0))
    bad_length = ip(0, struct.pack("!HHHH", port, port, 99, 0) + b"\xc0")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        while not stop.wait(0.0005):
            raw.sendto(fragment, ("127.0.0.1", 0))
            raw.sendto(bad_length, ("127.0.0.1", 0))


class FingerprintTest(unittest.TestCase):
    @unittest.skipUnless(os.getenv("JA4L_TEST"), "JA4L packet capture is not enabled")
    def test_ja4l_packet_timestamps(self):
        # Independent packet-socket observation, using FoxIO's A..F equations.
        # Linux SO_TIMESTAMPNS is 35; Python does not expose it on every build.
        timestampns = getattr(socket, "SO_TIMESTAMPNS", 35)
        # ETH_P_ALL transmit taps share one kernel timestamp on loopback;
        # loopback receive copies may receive different timestamps per socket.
        with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003)) as capture:
            capture.bind(("lo", 0))
            capture.setsockopt(socket.SOL_SOCKET, timestampns, 1)
            capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            stop = threading.Event()
            noise = threading.Thread(target=send_kernel_dropped_packets, args=(HTTP_PORT, stop))
            noise.start()
            try:
                response, _ = request(HTTP_PORT)
            finally:
                stop.set()
                noise.join()
            packets = []
            while True:
                try:
                    packet, controls, flags, address = capture.recvmsg(
                        65575, socket.CMSG_SPACE(struct.calcsize("@ll")), socket.MSG_DONTWAIT
                    )
                except BlockingIOError:
                    break
                if address[2] != socket.PACKET_OUTGOING or len(packet) < 40:
                    continue
                if packet[0] >> 4 == 4 and packet[9] == 6:
                    offset = (packet[0] & 15) * 4
                    end, ttl = int.from_bytes(packet[2:4]), packet[8]
                elif packet[0] >> 4 == 6 and packet[6] == 6 and len(packet) >= 60:
                    offset = 40
                    end, ttl = 40 + int.from_bytes(packet[4:6]), packet[7]
                else:
                    continue
                sport, dport, seq, ack = struct.unpack_from("!HHII", packet, offset)
                if HTTP_PORT not in (sport, dport):
                    continue
                self.assertFalse(flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
                stamp = None
                for level, kind, value in controls:
                    if level == socket.SOL_SOCKET and kind == timestampns:
                        seconds, nanos = struct.unpack_from("@ll", value)
                        stamp = seconds * 1_000_000_000 + nanos
                self.assertIsNotNone(stamp)
                payload = end - offset - (packet[offset + 12] >> 4) * 4
                packets.append((sport, dport, seq, ack, packet[offset + 13], payload, stamp, ttl))

        syn = next(p for p in packets if p[1] == HTTP_PORT and p[4] & 0x12 == 0x02)
        client_port = syn[0]
        synack = next(p for p in packets if p[0] == HTTP_PORT and p[1] == client_port and p[4] & 0x12 == 0x12)
        ack = next(p for p in packets if p[0] == client_port and p[4] & 0x12 == 0x10 and not p[5]
                   and p[2] == (syn[2] + 1) % 2**32 and p[3] == (synack[2] + 1) % 2**32)
        client_first = next(p for p in packets if p[0] == client_port and p[5] and p[6] >= ack[6])
        server_first = next(p for p in packets if p[0] == HTTP_PORT and p[1] == client_port and p[5] and p[6] >= client_first[6])
        client_next = next(p for p in packets if p[0] == client_port and p[5] and p[6] > server_first[6])
        client_tcp = ack[6] - synack[6]
        client_app = client_next[6] - server_first[6]
        values = dict(line.split(": ", 1) for line in response.splitlines() if ": " in line)
        self.assertEqual(values["ja4l"], f"{client_tcp // 2000}_{syn[7]}_{client_app // 2000}")
        self.assertEqual(values["ja4l_delta"], str(
            (Decimal(client_app) / client_tcp).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
        ))

    def test_ja4h_cookies(self):
        response, _ = request(
            HTTP_PORT,
            http_request=(
                b"GET / HTTP/1.1\r\nHost: localhost\r\n"
                b"Cookie: a-b=1; a=first; z=last\r\n"
                b"Referer: https://example.org/\r\n"
                b"Accept-Language: en-US,en;q=0.5\r\n"
                b"Cookie: a=second; token=x=y\r\n"
                b"Connection: close\r\n\r\n"
            ),
        )
        values = dict(line.split(": ", 1) for line in response.splitlines() if ": " in line)
        materials = (
            "Host,Accept-Language,Connection",
            "a,a,a-b,token,z",
            "a=first,a=second,a-b=1,token=x=y,z=last",
        )
        self.assertEqual(values["ja4h_r"], "ge11cr03enus_" + "_".join(materials))
        self.assertEqual(
            values["ja4h"],
            "ge11cr03enus_" + "_".join(
                hashlib.sha256(value.encode()).hexdigest()[:12] for value in materials
            ),
        )

    def test_client_ja4x_certificate_oids(self):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
        except ImportError:
            self.skipTest("cryptography is not installed")
        # Issuer/subject C, OU, CN and extensions SKI, AKI, Basic Constraints, in order.
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Web"),
            x509.NameAttribute(NameOID.COMMON_NAME, "client.example"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        materials = ("550406,55040b,550403", "550406,55040b,550403", "551d0e,551d23,551d13")
        expected = "_".join(hashlib.sha256(value.encode()).hexdigest()[:12] for value in materials)
        with tempfile.NamedTemporaryFile(suffix=".pem") as identity:
            identity.write(cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            identity.flush()
            for port in (HTTP_PORT, STREAM_PORT):
                with self.subTest(port=port):
                    response, _ = request(port)
                    values = dict(line.split(": ", 1) for line in response.splitlines() if ": " in line)
                    self.assertEqual(values["client_ja4x"], "")
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.load_cert_chain(identity.name)
                    response, _ = request(port, context=context)
                    values = dict(line.split(": ", 1) for line in response.splitlines() if ": " in line)
                    self.assertEqual(values["client_ja4x"], expected)
                    self.assertEqual(values["client_ja4x_r"], "_".join(materials))

    @unittest.skipUnless(
        sys.platform.startswith("linux") and hasattr(socket, "TCP_MAXSEG"),
        "JA4T capture requires Linux and TCP_MAXSEG",
    )
    def test_ja4t_saved_syn(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1200)
            connection.connect((HOST, HTTP_PLAIN_PORT))
            connection.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            chunks = []
            while chunk := connection.recv(8192):
                chunks.append(chunk)
        values = dict(line.split(": ", 1) for line in b"".join(chunks).decode().splitlines() if ": " in line)
        self.assertRegex(values["ja4t"], r"^\d+_(?:\d+-)*\d+_1200_\d+$")
        self.assertEqual(values["client_ja4x"], "")
        self.assertEqual(values["ja4h_r"], "ge11nn020000_Host,Connection__")

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
    def test_http2_headers_priority(self):
        response = request_many_http2_settings()
        fingerprint = next(
            line.removeprefix("h2fp: ")
            for line in response.splitlines()
            if line.startswith("h2fp: ")
        )
        self.assertEqual(fingerprint.split("|")[2], "1:1:3:256")

    @unittest.skipUnless(H2Connection, "hyper-h2 is not installed")
    def test_many_http2_settings(self):
        response = request_many_http2_settings()
        values = dict(
            line.split(": ", 1)
            for line in response.splitlines()
            if ": " in line
        )
        settings = values["h2fp"].split("|", 1)[0]
        # :authority must not become an invented Host field in JA4H.
        self.assertEqual(values["ja4h_r"], "ge20nn000000___")
        self.assertEqual(values["ja4h"], "ge20nn000000_" + "_".join(["0" * 12] * 3))
        self.assertRegex(values["ja4t"], r"^\d+_(?:\d+-)*\d+_\d+_\d+$")
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
