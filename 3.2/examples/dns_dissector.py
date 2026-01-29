"""
AI-Generated Dissector for DNS
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    FlagsField,
    IntField,
    IPField,
    PacketListField,
    ShortField,
    StrLenField,
    StrField,
    XShortEnumField,
    XShortField,
)
from scapy.layers.inet import UDP

# DNS Message Flags
DNS_FLAG_QR = 0x8000
DNS_FLAG_OPCODE = 0x7800
DNS_FLAG_AA = 0x800
DNS_FLAG_TC = 0x400
DNS_FLAG_RD = 0x200
DNS_FLAG_RA = 0x100
DNS_FLAG_Z = 0x80
DNS_FLAG_AD = 0x20
DNS_FLAG_CD = 0x10

# DNS Question Types
DNS_QTYPE_A = 1
DNS_QTYPE_NS = 2
DNS_QTYPE_MD = 3
DNS_QTYPE_MF = 4
DNS_QTYPE_CNAME = 5
DNS_QTYPE_SOA = 6
DNS_QTYPE_MB = 7
DNS_QTYPE_MG = 8
DNS_QTYPE_MR = 9
DNS_QTYPE_NULL = 10
DNS_QTYPE_WKS = 11
DNS_QTYPE_PTR = 12
DNS_QTYPE_HINFO = 13
DNS_QTYPE_MINFO = 14
DNS_QTYPE_MX = 15
DNS_QTYPE_TXT = 16
DNS_QTYPE_RP = 17
DNS_QTYPE_AFXR = 18
DNS_QTYPE_MAILB = 19
DNS_QTYPE_MAILA = 20
DNS_QTYPE_AAAA = 28
DNS_QTYPE_LOC = 29
DNS_QTYPE_NXT = 30
DNS_QTYPE_SRV = 33
DNS_QTYPE_ATMA = 35
DNS_QTYPE_NAPTR = 35
DNS_QTYPE_KX = 36
DNS_QTYPE_CERT = 37
DNS_QTYPE_A6 = 38
DNS_QTYPE_DNAME = 39
DNS_QTYPE_SSHFP = 44
DNS_QTYPE_IPSECKEY = 45
DNS_QTYPE_RRSIG = 46
DNS_QTYPE_NSEC = 47
DNS_QTYPE_DS = 43
DNS_QTYPE_NIMLOC = 36
DNS_QTYPE_ALL = 255

# DNS Question Classes
DNS_CLASS_IN = 1
DNS_CLASS_CS = 2
DNS_CLASS_CH = 3
DNS_CLASS_HS = 4
DNS_CLASS_NONE = 254
DNS_CLASS_ANY = 255

class DNS(Packet):
    name = "DNS"
    fields_desc = [
        ByteEnumField("id", 0, 2),
        ShortField("flags", 0),
        XShortField("qdc", 0),
        XShortField("anc", 0),
    ]

    def guess_payload_class(self, payload):
        return UDP.payload_guess(self)

    def post_build(self, p, pay):
        if self.flags != 0:
            p = p[:2] + bytes([self.flags >> 8 & 0xFF]) + bytes([self.flags & 0xFF]) + p[4:]
        return p + pay

    def extract_padding(self, p):
        return ""

class DNSQR(Packet):
    name = "DNS Question Record"
    fields_desc = [
        XShortField("qname", 0),
        XShortField("qtype", 0),
        XShortField("qclass", 0),
    ]

    def guess_payload_class(self, payload):
        return DNS.payload_guess(self)

    def post_build(self, p, pay):
        if self.qname != 0:
            p = p[:2] + bytes([self.qname >> 8 & 0xFF]) + bytes([self.qname & 0xFF]) + p[4:]
        return p + pay

    def extract_padding(self, p):
        return ""

class DNSRR(Packet):
    name = "DNS Resource Record"
    fields_desc = [
        XShortField("name", 0),
        XShortField("type", 0),
        XShortField("class", 0),
        XShortField("ttl", 0),
        XShortField("rdlength", 0),
        StrLenField("rdata", "", length_from=lambda pkt: pkt.rdlength),
    ]

    def guess_payload_class(self, payload):
        return DNS.payload_guess(self)

    def post_build(self, p, pay):
        if self.name != 0:
            p = p[:2] + bytes([self.name >> 8 & 0xFF]) + bytes([self.name & 0xFF]) + p[4:]
        return p + pay

    def extract_padding(self, p):
        return ""

class DNSQD(DNS):
    name = "DNS Query"
    fields_desc = [
        ByteEnumField("id", 0, 2),
        ShortField("flags", 0),
        XShortField("qdc", 0),
        XShortField("anc", 0),
        PacketListField("questions", [], DNSQR, length_from=lambda pkt: pkt.qdc),
    ]

    def guess_payload_class(self, payload):
        return UDP.payload_guess(self)

    def post_build(self, p, pay):
        if self.flags != 0:
            p = p[:2] + bytes([self.flags >> 8 & 0xFF]) + bytes([self.flags & 0xFF]) + p[4:]
        return p + pay

    def extract_padding(self, p):
        return ""

class DNSRD(DNS):
    name = "DNS Response"
    fields_desc = [
        ByteEnumField("id", 0, 2),
        ShortField("flags", 0),
        XShortField("qdc", 0),
        XShortField("anc", 0),
        PacketListField("questions", [], DNSQR, length_from=lambda pkt: pkt.qdc),
        PacketListField("answers", [], DNSRR, length_from=lambda pkt: pkt.anc),
    ]

    def guess_payload_class(self, payload):
        return UDP.payload_guess(self)

    def post_build(self, p, pay):
        if self.flags != 0:
            p = p[:2] + bytes([self.flags >> 8 & 0xFF]) + bytes([self.flags & 0xFF]) + p[4:]
        return p + pay

    def extract_padding(self, p):
        return ""

bind_layers(UDP, DNSQD, dport=53)
bind_layers(UDP, DNSRD, sport=53)
bind_layers(UDP, DNSRD, dport=53)