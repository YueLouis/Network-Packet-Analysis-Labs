"""
AI-Generated Dissector for DNS
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ConditionalField,
    Field,
    FieldLenField,
    IPField,
    IntEnumField,
    IntField,
    ShortEnumField,
    ShortField,
    StrLenField,
    StrField,
    XShortEnumField,
    XShortField,
    XByteEnumField,
    XByteField,
    XIntEnumField,
    XIntField,
    XStrLenField,
    XStrField,
)
from scapy.layers.inet import UDP

# DNS Message Types
DNS_MESSAGE_TYPES = {
    0x0000: "QUERY",
    0x0001: "RESPONSE",
}

# DNS Class Types
DNS_CLASS_TYPES = {
    0x0001: "IN",
}

# DNS Opcode Types
DNS_OPCODE_TYPES = {
    0x0000: "QUERY",
    0x0001: "RESPONSE",
    0x0020: "TRUNCATED",
}

# DNS RCODE Types
DNS_RCODE_TYPES = {
    0x0000: "NO_ERROR",
    0x0001: "FORMAT_ERROR",
    0x0002: "SERVER_FAILURE",
    0x0003: "NAME_ERROR",
    0x0004: "NOT_IMPLEMENTED",
    0x0005: "REFUSED",
}

# DNS QTYPE Types
DNS_QTYPE_TYPES = {
    0x0001: "A",
    0x0002: "NS",
    0x0005: "CNAME",
    0x0006: "SOA",
    0x0008: "PTR",
    0x0009: "MX",
    0x000C: "PTR",
    0x000D: "MD",
    0x000E: "MF",
    0x0010: "CNAME",
    0x0011: "SOA",
    0x0012: "MB",
    0x0013: "MG",
    0x0014: "MR",
    0x0015: "NULL",
    0x0016: "WKS",
    0x0017: "PTR",
    0x0018: "HINFO",
    0x0019: "MINFO",
    0x001A: "MX",
    0x001B: "TXT",
    0x001C: "RP",
    0x001D: "AFSDB",
    0x001E: "X25",
    0x001F: "ISDN",
    0x0020: "RT",
    0x0021: "NSAP",
    0x0022: "NSAP_PTR",
    0x0023: "SIG",
    0x0024: "KEY",
    0x0025: "PX",
    0x0026: "GPOS",
    0x0027: "AAAA",
    0x0028: "LOC",
    0x0029: "NXT",
    0x002A: "EID",
    0x002B: "NIMLOC",
    0x002C: "SRV",
    0x002D: "ATMA",
    0x002E: "NAPTR",
    0x002F: "KX",
    0x0030: "CERT",
    0x0031: "A6",
    0x0032: "DNAME",
    0x0033: "SINK",
    0x0034: "OPT",
    0x0035: "APL",
    0x0036: "DS",
    0x0037: "SSHFP",
    0x0038: "IPSECKEY",
    0x0039: "RRSIG",
    0x003A: "NSEC",
    0x003B: "DNSKEY",
    0x003C: "DHCID",
    0x003D: "NSEC3",
    0x003E: "NSEC3PARAM",
    0x003F: "TLSA",
    0x0040: "SMIMEA",
    0x0041: "HIP",
    0x0042: "NINFO",
    0x0043: "RKEY",
    0x0044: "TALINK",
    0x0045: "CDS",
    0x0046: "CDNSKEY",
    0x0047: "OPENPGPKEY",
    0x0048: "CSYNC",
    0x0049: "ZONEMD",
    0x00FF: "Reserved",
}

# DNS QCLASS Types
DNS_QCLASS_TYPES = {
    0x0001: "IN",
}

# DNS RR Types
DNS_RR_TYPES = {
    0x0001: "A",
    0x0002: "NS",
    0x0005: "CNAME",
    0x0006: "SOA",
    0x0008: "PTR",
    0x0009: "MX",
    0x000C: "PTR",
    0x000D: "MD",
    0x000E: "MF",
    0x0010: "CNAME",
    0x0011: "SOA",
    0x0012: "MB",
    0x0013: "MG",
    0x0014: "MR",
    0x0015: "NULL",
    0x0016: "WKS",
    0x0017: "PTR",
    0x0018: "HINFO",
    0x0019: "MINFO",
    0x001A: "MX",
    0x001B: "TXT",
    0x001C: "RP",
    0x001D: "AFSDB",
    0x001E: "X25",
    0x001F: "ISDN",
    0x0020: "RT",
    0x0021: "NSAP",
    0x0022: "NSAP_PTR",
    0x0023: "SIG",
    0x0024: "KEY",
    0x0025: "PX",
    0x0026: "GPOS",
    0x0027: "AAAA",
    0x0028: "LOC",
    0x0029: "NXT",
    0x002A: "EID",
    0x002B: "NIMLOC",
    0x002C: "SRV",
    0x002D: "ATMA",
    0x002E: "NAPTR",
    0x002F: "KX",
    0x0030: "CERT",
    0x0031: "A6",
    0x0032: "DNAME",
    0x0033: "SINK",
    0x0034: "OPT",
    0x0035: "APL",
    0x0036: "DS",
    0x0037: "SSHFP",
    0x0038: "IPSECKEY",
    0x0039: "RRSIG",
    0x003A: "NSEC",
    0x003B: "DNSKEY",
    0x003C: "DHCID",
    0x003D: "NSEC3",
    0x003E: "NSEC3PARAM",
    0x003F: "TLSA",
    0x0040: "SMIMEA",
    0x0041: "HIP",
    0x0042: "NINFO",
    0x0043: "RKEY",
    0x0044: "TALINK",
    0x0045: "CDS",
    0x0046: "CDNSKEY",
    0x0047: "OPENPGPKEY",
    0x0048: "CSYNC",
    0x0049: "ZONEMD",
    0x00FF: "Reserved",
}

# DNS RR CLASS Types
DNS_RR_CLASS_TYPES = {
    0x0001: "IN",
}

class DNS(Packet):
    name = "DNS"
    fields_desc = [
        ByteEnumField("id", 0, 2, dns_message_types=DNS_MESSAGE_TYPES),
        ShortField("flags", 0),
        ShortField("qdc", 0),
        ShortField("anc", 0),
        ShortField("ns", 0),
        ShortField("ar", 0),
        ConditionalField(
            FieldLenField(
                "qdcount", None, 1, length_of="qd", fmt="H"
            ),
            lambda pkt: pkt.qd,
        ),
        ConditionalField(
            FieldLenField(
                "ancount", None, 1, length_of="an", fmt="