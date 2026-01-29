"""
AI-Generated Dissector for HTTP
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ConditionalField,
    Field,
    FieldLenField,
    IntField,
    IPField,
    PacketListField,
    ShortEnumField,
    StrLenField,
    StrFixedLenField,
    XShortEnumField,
    XIntField,
    XShortEnumField,
    XStrLenField,
    XStrFixedLenField,
)
from scapy.layers.inet import IP, TCP

class HTTP(Packet):
    name = "HTTP"
    fields_desc = [
        # HTTP Version
        ByteEnumField("version_major", 0, {9: "HTTP/1.0", 10: "HTTP/1.1"}),
        ByteEnumField("version_minor", 0, {0: "HTTP/1.0", 1: "HTTP/1.1"}),
        # Request/Response
        ByteEnumField("request_method", 0, {
            0x01: "GET",
            0x02: "HEAD",
            0x03: "POST",
            0x04: "PUT",
            0x05: "DELETE",
            0x06: "CONNECT",
            0x07: "OPTIONS",
            0x08: "TRACE",
        }),
        # HTTP Status Code
        XShortEnumField("status_code", 0, {
            100: "Continue",
            101: "Switching Protocols",
            200: "OK",
            201: "Created",
            202: "Accepted",
            203: "Non-Authoritative Information",
            204: "No Content",
            205: "Reset Content",
            206: "Partial Content",
            300: "Multiple Choices",
            301: "Moved Permanently",
            302: "Found",
            303: "See Other",
            304: "Not Modified",
            305: "Use Proxy",
            307: "Temporary Redirect",
            400: "Bad Request",
            401: "Unauthorized",
            402: "Payment Required",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            406: "Not Acceptable",
            407: "Proxy Authentication Required",
            408: "Request Time-out",
            409: "Conflict",
            410: "Gone",
            411: "Length Required",
            412: "Precondition Failed",
            413: "Request Entity Too Large",
            414: "Request-URI Too Large",
            415: "Unsupported Media Type",
            416: "Requested range not satisfiable",
            417: "Expectation Failed",
            500: "Internal Server Error",
            501: "Not Implemented",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Time-out",
            505: "HTTP Version not supported",
        }),
        # Request/Response Headers
        ConditionalField(
            FieldLenField("header_len", None, length_of="headers"),
            condition=lambda pkt: pkt.request_method != 0x07,
        ),
        ConditionalField(
            PacketListField(
                "headers",
                [],
                [HTTPHeaderField],
                length_from=lambda pkt: pkt.header_len,
            ),
            condition=lambda pkt: pkt.request_method != 0x07,
        ),
        # Request/Response Body
        ConditionalField(
            FieldLenField("body_len", None, length_of="body"),
            condition=lambda pkt: pkt.request_method == 0x07,
        ),
        ConditionalField(
            StrLenField("body", "", length_from=lambda pkt: pkt.body_len),
            condition=lambda pkt: pkt.request_method == 0x07,
        ),
    ]

    def extract_padding(self, s):
        return ""

    def guess_payload_class(self, payload):
        return HTTP

    def post_dissect(self):
        if self.request_method == 0x07:
            self.body = self.getfieldval("body")
        else:
            self.headers = self.getfieldval("headers")

class HTTPHeaderField(Packet):
    name = "HTTP Header"
    fields_desc = [
        # Header Field Name
        StrLenField("name", "", length_from=lambda pkt: pkt.getfieldval("len")),
        # Header Field Value
        StrLenField("value", "", length_from=lambda pkt: pkt.getfieldval("len")),
    ]

    def extract_padding(self, s):
        return ""

    def guess_payload_class(self, payload):
        return HTTPHeaderField

bind_layers(TCP, HTTP, dport=80)
bind_layers(TCP, HTTP, sport=80)

# Usage examples
from scapy.all import *

# Parse HTTP packet from a capture file
pkts = rdpcap("capture.pcap")
for pkt in pkts:
    if HTTP in pkt:
        print(pkt.show())

# Create an HTTP packet
http_packet = HTTP(
    version_major=10,
    version_minor=1,
    request_method=1,
    status_code=200,
    headers=[HTTPHeaderField(name="Host", value="example.com"), HTTPHeaderField(name="User-Agent", value="Mozilla/5.0")],
    body="Hello, World!",
)
print(http_packet.show())