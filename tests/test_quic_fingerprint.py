import asyncio
import csv
import hashlib
import io
import json
import os
import socket
import ssl
import unittest
import urllib.error
import urllib.request

try:
    import httpx
except ImportError:
    httpx = None

try:
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated
    from aioquic.quic.packet import QuicProtocolVersion
except ImportError:
    connect = None
    QuicConnectionProtocol = object
    H3Connection = object


HOST = os.getenv("NGINX_HOST", "127.0.0.1")
HTTP_PORT = int(os.getenv("NGINX_HTTP_PORT", "4433"))
HTTP3_PORT = int(os.getenv("NGINX_HTTP3_PORT", "4434"))
RESERVED_VERSION = 0x1A2A3A4A
PUBLIC_PERK_TEXT = (
    "1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p|"
    "12584:4f524947;3:1472;6:6291456;12583:AUTO;32:65536;15:;"
    "4:15728640;9:103;5:6291456;GREASE;7:6291456;"
    "17:1@1,GREASE;8:100;1:30000"
)
PUBLIC_PERK_HASH = "1f49997bcd1d1ad4540e50056999527c"
PUBLIC_PERK_TEXT_NORMALIZED = (
    "1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p|"
    "1:30000;3:1472;4:15728640;5:6291456;6:6291456;7:6291456;"
    "8:100;9:103;15:;17:1@1,GREASE;32:65536;12583:AUTO;"
    "12584:4f524947;GREASE"
)
PUBLIC_PERK_HASH_NORMALIZED = "94776d419fc3a7164f0ca93712bb9bd5"
PUBLIC_QUIC_JA4 = "q13d0312h3_55b375c5d22e_06cda9e17597"
PUBLIC_HTTPX_AKAMAI = (
    "1:4096;2:0;4:65535;5:16384;3:100;6:65536|"
    "16777216|0|m,a,s,p"
)
PUBLIC_HTTPX_AKAMAI_HASH = "29e6a0e9b360185223ec1278a845fdb1"
IANA_PERMANENT_QUIC_TRANSPORT_PARAMETERS = {
    *range(0x00, 0x12),
    0x20,
    0x3E,
    0x2AB2,
}
IANA_HTTP2_SETTINGS = {1, 2, 3, 4, 5, 6, 8, 9, 0x10, 0x4D44}
IANA_HTTP3_SETTINGS = {1, 6, 7, 8, 0x33, 0x4D44}


def perk_text(settings, pseudo_headers, transport_parameters):
    return f"{settings}|{','.join(pseudo_headers)}|{transport_parameters}"


class Http3Client(QuicConnectionProtocol):
    http_connection_class = H3Connection

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None
        self.responses = {}

    async def get(self, authority, path="/"):
        stream_id = self._quic.get_next_available_stream_id()
        waiter = self._loop.create_future()
        self.responses[stream_id] = (waiter, bytearray())
        self.http.send_headers(
            stream_id,
            [
                (b":method", b"GET"),
                (b":authority", authority.encode()),
                (b":scheme", b"https"),
                (b":path", path.encode()),
            ],
            end_stream=True,
        )
        self.transmit()
        return await asyncio.wait_for(waiter, 5)

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = self.http_connection_class(self._quic)

        if self.http is not None:
            for http_event in self.http.handle_event(event):
                response = self.responses.get(http_event.stream_id)
                if response is None:
                    continue
                waiter, body = response
                if isinstance(http_event, DataReceived):
                    body.extend(http_event.data)
                if (
                    isinstance(http_event, (DataReceived, HeadersReceived))
                    and http_event.stream_ended
                    and not waiter.done()
                ):
                    waiter.set_result(bytes(body))
                    self.responses.pop(http_event.stream_id, None)

        if isinstance(event, ConnectionTerminated):
            for waiter, _ in self.responses.values():
                if not waiter.done():
                    waiter.set_exception(ConnectionError(event.reason_phrase))


class ManySettingsH3Connection(H3Connection):
    def _get_local_settings(self):
        settings = super()._get_local_settings()
        settings.update({0x100 + index: index for index in range(260)})
        return settings


class PerkTransportClient(Http3Client):
    http_connection_class = ManySettingsH3Connection

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        serialize = self._quic._serialize_transport_parameters

        def serialize_with_initial_rtt():
            # Unknown 0x10001, initial_max_path_id=7, and initial_rtt=310080.
            extra = bytes.fromhex(
                "8001000101ff3e01077127048004bb40"
            )
            return extra + serialize()

        self._quic._serialize_transport_parameters = serialize_with_initial_rtt


def send_version_negotiation_probes(count):
    packet = (
        b"\xc0"
        + RESERVED_VERSION.to_bytes(4, "big")
        + b"\x08abcdefgh"
        + b"\x08ABCDEFGH"
    )
    probes = []
    try:
        for _ in range(count):
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.bind(("0.0.0.0", 0))
            probe.settimeout(2)
            probes.append(probe)
            probe.sendto(packet, (HOST, HTTP3_PORT))
            response, _ = probe.recvfrom(2048)
            if len(response) < 5 or response[1:5] != b"\0\0\0\0":
                raise RuntimeError("invalid QUIC Version Negotiation response")
    except Exception:
        for probe in probes:
            probe.close()
        raise

    local_port = probes[0].getsockname()[1]
    probes[0].close()
    return local_port, probes[1:]


async def request(local_port, protocol=Http3Client):
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
    )
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]
    async with connect(
        HOST,
        HTTP3_PORT,
        configuration=configuration,
        create_protocol=protocol,
        local_port=local_port,
    ) as client:
        authority = f"{HOST}:{HTTP3_PORT}"
        return await client.get(authority), await client.get(authority)


async def public_perk_request():
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
    )
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]
    async with asyncio.timeout(20):
        async with connect(
            "fp.impersonate.pro",
            443,
            configuration=configuration,
            create_protocol=Http3Client,
        ) as client:
            return await client.get("fp.impersonate.pro", "/api/http3")


class FingerprintFormatTest(unittest.TestCase):
    def test_public_akamai_fixture(self):
        settings, window_update, priority, pseudo_headers = (
            PUBLIC_HTTPX_AKAMAI.split("|")
        )
        self.assertEqual(len(settings.split(";")), 6)
        self.assertEqual(window_update, "16777216")
        self.assertEqual(priority, "0")
        self.assertEqual(pseudo_headers, "m,a,s,p")
        self.assertEqual(
            hashlib.md5(PUBLIC_HTTPX_AKAMAI.encode()).hexdigest(),
            PUBLIC_HTTPX_AKAMAI_HASH,
        )

    def test_public_perk_fixture(self):
        settings, pseudo_headers, transport_parameters = PUBLIC_PERK_TEXT.split(
            "|", 2
        )
        self.assertEqual(
            perk_text(settings, pseudo_headers.split(","), transport_parameters),
            PUBLIC_PERK_TEXT,
        )
        self.assertEqual(
            hashlib.md5(PUBLIC_PERK_TEXT.encode()).hexdigest(),
            PUBLIC_PERK_HASH,
        )
        normalized_settings, normalized_pseudo, normalized_parameters = (
            PUBLIC_PERK_TEXT_NORMALIZED.split("|", 2)
        )
        self.assertEqual(normalized_settings, settings)
        self.assertEqual(normalized_pseudo, pseudo_headers)
        self.assertEqual(
            perk_text(
                normalized_settings,
                normalized_pseudo.split(","),
                normalized_parameters,
            ),
            PUBLIC_PERK_TEXT_NORMALIZED,
        )
        self.assertEqual(
            hashlib.md5(PUBLIC_PERK_TEXT_NORMALIZED.encode()).hexdigest(),
            PUBLIC_PERK_HASH_NORMALIZED,
        )

    @unittest.skipUnless(
        os.getenv("PUBLIC_JA4_COMPAT"),
        "PUBLIC_JA4_COMPAT is not set",
    )
    def test_public_ja4_lookup(self):
        url = f"https://usefoil.com/ja4/{PUBLIC_QUIC_JA4}"
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "nginx-ssl-fingerprint compatibility test"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                page = response.read().decode()
        except (OSError, urllib.error.URLError) as exc:
            self.skipTest(f"public JA4 lookup unavailable: {type(exc).__name__}")

        self.assertIn(PUBLIC_QUIC_JA4, page)
        self.assertIn("Chromium (QUIC)", page)

    @unittest.skipUnless(
        os.getenv("PUBLIC_IANA_COMPAT"),
        "PUBLIC_IANA_COMPAT is not set",
    )
    def test_iana_quic_transport_parameter_registry(self):
        url = "https://www.iana.org/assignments/quic/quic-transport.csv"
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "nginx-ssl-fingerprint registry test"},
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                rows = csv.DictReader(io.StringIO(response.read().decode()))
                permanent = {
                    int(row["Value"], 16)
                    for row in rows
                    if row["Status"] == "permanent"
                }
        except (OSError, urllib.error.URLError) as exc:
            self.skipTest(f"IANA registry unavailable: {type(exc).__name__}")

        self.assertEqual(
            permanent,
            IANA_PERMANENT_QUIC_TRANSPORT_PARAMETERS,
            "review new or reclassified QUIC transport parameters",
        )

    @unittest.skipUnless(
        os.getenv("PUBLIC_IANA_COMPAT"),
        "PUBLIC_IANA_COMPAT is not set",
    )
    def test_iana_http_settings_registries(self):
        registries = (
            (
                "https://www.iana.org/assignments/http2-parameters/settings.csv",
                "Code",
                "Name",
                IANA_HTTP2_SETTINGS,
            ),
            (
                "https://www.iana.org/assignments/http3-parameters/"
                "http3-parameters-settings.csv",
                "Value",
                "Setting Name",
                IANA_HTTP3_SETTINGS,
            ),
        )

        for url, value_field, name_field, expected in registries:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "nginx-ssl-fingerprint registry test"},
            )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    rows = csv.DictReader(
                        io.StringIO(response.read().decode())
                    )
                    assigned = {
                        int(row[value_field], 16)
                        for row in rows
                        if row[name_field] not in ("Reserved", "Unassigned")
                    }
            except (OSError, urllib.error.URLError) as exc:
                self.skipTest(
                    f"IANA registry unavailable: {type(exc).__name__}"
                )

            self.assertEqual(
                assigned,
                expected,
                f"review new HTTP settings in {url}",
            )


@unittest.skipUnless(httpx, "httpx with HTTP/2 support is not installed")
class Http2CompatibilityTest(unittest.TestCase):
    @unittest.skipUnless(
        os.getenv("PUBLIC_HTTP2_COMPAT"),
        "PUBLIC_HTTP2_COMPAT is not set",
    )
    def test_public_akamai_compatibility(self):
        with httpx.Client(
            http2=True,
            verify=False,
            trust_env=False,
            timeout=15,
        ) as client:
            local_response = client.get(f"https://{HOST}:{HTTP_PORT}/")
            local_response.raise_for_status()
        self.assertEqual(local_response.http_version, "HTTP/2")
        local_values = dict(
            line.split(": ", 1)
            for line in local_response.text.splitlines()
            if ": " in line
        )

        try:
            with httpx.Client(
                http2=True,
                trust_env=False,
                timeout=15,
            ) as client:
                public_response = client.get(
                    "https://fp.impersonate.pro/api/http2"
                )
                public_response.raise_for_status()
        except httpx.HTTPError as exc:
            self.skipTest(
                f"public HTTP/2 endpoint unavailable: {type(exc).__name__}"
            )

        self.assertEqual(public_response.http_version, "HTTP/2")
        public = public_response.json()["http2"]
        self.assertEqual(local_values["h2fp"], public["akamai_text"])
        self.assertEqual(
            hashlib.md5(local_values["h2fp"].encode()).hexdigest(),
            public["akamai_hash"],
        )


@unittest.skipUnless(connect, "aioquic is not installed")
class QuicFingerprintTest(unittest.TestCase):
    def test_http3_fingerprint(self):
        local_port, probes = send_version_negotiation_probes(300)
        try:
            responses = asyncio.run(request(local_port, PerkTransportClient))
        finally:
            for probe in probes:
                probe.close()
        self.assertEqual(responses[0], responses[1])
        body = responses[0].decode()
        values = dict(
            line.split(": ", 1)
            for line in body.splitlines()
            if ": " in line
        )

        self.assertTrue(values["ja4"].startswith("q13"))
        self.assertEqual(values["alpn"], "h3")
        self.assertEqual(values["quic_version"], "00000001")
        self.assertGreaterEqual(int(values["quic_initial_size"]), 1200)
        self.assertGreater(int(values["quic_dcid_len"]), 0)
        self.assertGreater(int(values["quic_scid_len"]), 0)
        self.assertTrue(values["quic_tp"])
        self.assertRegex(values["quic_tp"], r"(?:^|;)15:(?:;|$)")
        self.assertRegex(values["quic_tp"], r"(?:^|;)62:7(?:;|$)")
        self.assertRegex(values["quic_tp"], r"(?:^|;)65537:ff(?:;|$)")
        self.assertRegex(values["quic_tp"], r"(?:^|;)12583:AUTO(?:;|$)")
        self.assertTrue(values["quic_tp_normalized"])
        self.assertRegex(
            values["quic_tp_normalized"],
            r"(?:^|;)62:7(?:;|$)",
        )
        self.assertRegex(
            values["quic_tp_normalized"],
            r"(?:^|;)65537:ff(?:;|$)",
        )
        self.assertRegex(
            values["quic_tp_normalized"],
            r"(?:^|;)12583:AUTO(?:;|$)",
        )
        self.assertRegex(values["quic_tp_raw"], r"^[0-9a-f]+$")
        self.assertEqual(values["quic_retry"], "1")
        self.assertEqual(
            values["quic_vn"],
            f"{RESERVED_VERSION:08x}>00000001",
        )
        self.assertTrue(values["h3_settings"])
        self.assertNotIn("TRUNCATED", values["h3_settings"])
        self.assertEqual(len(values["h3_settings"].split(";")), 264)
        self.assertRegex(values["h3_settings"], r"(?:^|;)1:\d+(?:;|$)")
        self.assertRegex(values["h3_settings"], r"(?:^|;)7:\d+(?:;|$)")
        settings = {
            int(item.split(":", 1)[0]): int(item.split(":", 1)[1])
            for item in values["h3_settings"].split(";")
            if ":" in item
        }
        self.assertEqual(
            values["h3_qpack"],
            f'{settings.get(1, 0)}:{settings.get(7, 0)}',
        )
        self.assertEqual(
            values["h3fp"],
            perk_text(
                values["h3_settings"],
                ["m", "a", "s", "p"],
                values["quic_tp"],
            ),
        )
        self.assertEqual(
            values["h3fp_hash"],
            hashlib.md5(values["h3fp"].encode()).hexdigest(),
        )
        self.assertEqual(values["h3perk"], values["h3fp"])
        self.assertEqual(values["h3perk_hash"], values["h3fp_hash"])
        self.assertEqual(
            values["h3perk_normalized"],
            perk_text(
                values["h3_settings"],
                ["m", "a", "s", "p"],
                values["quic_tp_normalized"],
            ),
        )
        self.assertEqual(
            values["h3perk_hash_normalized"],
            hashlib.md5(values["h3perk_normalized"].encode()).hexdigest(),
        )

    @unittest.skipUnless(
        os.getenv("PUBLIC_PERK_COMPAT"),
        "PUBLIC_PERK_COMPAT is not set",
    )
    def test_public_perk_compatibility(self):
        try:
            public = json.loads(asyncio.run(public_perk_request()))["http3"]
        except (ConnectionError, OSError, TimeoutError) as exc:
            self.skipTest(f"public HTTP/3 endpoint unavailable: {type(exc).__name__}")

        local = asyncio.run(request(0))[0].decode()
        values = dict(
            line.split(": ", 1)
            for line in local.splitlines()
            if ": " in line
        )
        self.assertEqual(values["h3fp"], public["perk_text"])
        self.assertEqual(values["h3fp_hash"], public["perk_hash"])
        self.assertEqual(
            values["h3perk_normalized"],
            public["perk_text_normalized"],
        )
        self.assertEqual(
            values["h3perk_hash_normalized"],
            public["perk_hash_normalized"],
        )


if __name__ == "__main__":
    unittest.main()
