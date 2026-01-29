"""
AI-Generated Dissector for HTTP
"""

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ConditionalField,
    Field,
    FieldLenField,
    IPField,
    IntField,
    LenField,
    PacketListField,
    ShortEnumField,
    StrLenField,
    StrField,
    XShortEnumField,
    XIntField,
    XStrLenField,
    XStrField,
)
from scapy.layers.inet import IP, TCP

# Define HTTP fields
class HTTPMethodField(Field):
    def m2i(self, x):
        return {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "HEAD": 4, "OPTIONS": 5, "CONNECT": 6, "PATCH": 7}[x]

    def i2m(self, x):
        return {v: k for k, v in self.m2i.items()}[x]

class HTTPVersionField(Field):
    def m2i(self, x):
        return {"HTTP/1.0": 0, "HTTP/1.1": 1}[x]

    def i2m(self, x):
        return {v: k for k, v in self.m2i.items()}[x]

class HTTPStatusField(Field):
    def m2i(self, x):
        return {"100-continue": 0, "200-ok": 1, "301-moved-permanently": 2, "302-found": 3, "304-not-modified": 4, "400-bad-request": 5, "401-unauthorized": 6, "403-forbidden": 7, "404-not-found": 8, "500-internal-server-error": 9}[x]

    def i2m(self, x):
        return {v: k for k, v in self.m2i.items()}[x]

class HTTPHeaderField(Field):
    def m2i(self, x):
        return {"Accept": 0, "Accept-Charset": 1, "Accept-Encoding": 2, "Accept-Language": 3, "Authorization": 4, "Cache-Control": 5, "Connection": 6, "Content-Type": 7, "Content-Length": 8, "Content-Range": 9, "Content-Disposition": 10, "Content-Transfer-Encoding": 11, "Cookie": 12, "Date": 13, "ETag": 14, "Expect": 15, "Expires": 16, "From": 17, "Host": 18, "If-Match": 19, "If-Modified-Since": 20, "If-None-Match": 21, "If-Range": 22, "If-Unmodified-Since": 23, "Last-Modified": 24, "Location": 25, "Max-Forwards": 26, "MIME-Version": 27, "Proxy-Authorization": 28, "Proxy-Authenticate": 29, "Proxy-Authenticate": 30, "Proxy-Connection": 31, "Range": 32, "Referer": 33, "Retry-After": 34, "Server": 35, "TE": 36, "Trailer": 37, "Transfer-Encoding": 38, "Upgrade": 39, "User-Agent": 40, "Vary": 41, "Via": 42, "Warning": 43, "WWW-Authenticate": 44, "X-Forwarded-For": 45, "X-Forwarded-Host": 46, "X-Forwarded-Proto": 47, "X-Powered-By": 48, "X-Real-IP": 49, "X-Request-Id": 50, "X-Runtime": 51, "X-UA-Compatible": 52, "X-Wap-Profile": 53, "X-Frame-Options": 54, "X-XSS-Protection": 55, "X-Content-Type-Options": 56, "X-Content-Security-Policy": 57, "X-Permitted-Cross-Domain-Policies": 58, "X-Download-Options": 59, "X-Generator": 60, "X-Robots-Tag": 61, "X-UA-Compatible": 62, "X-Wap-Profile": 63, "X-Content-Security-Policy-Report-Only": 64, "X-Frame-Options-Deny": 65, "X-Frame-Options-Sameorigin": 66, "X-Frame-Options-Allow-from": 67, "X-Frame-Options-Disallow": 68, "X-Frame-Options-Enable": 69, "X-Frame-Options-Sameorigin-allow-from": 70, "X-Frame-Options-Sameorigin-deny": 71, "X-Frame-Options-Sameorigin-Disallow": 72, "X-Frame-Options-Sameorigin-Enable": 73, "X-Frame-Options-Sameorigin-allow-from": 74, "X-Frame-Options-Sameorigin-deny": 75, "X-Frame-Options-Sameorigin-Disallow": 76, "X-Frame-Options-Sameorigin-Enable": 77, "X-Frame-Options-Sameorigin-allow-from": 78, "X-Frame-Options-Sameorigin-deny": 79, "X-Frame-Options-Sameorigin-Disallow": 80, "X-Frame-Options-Sameorigin-Enable": 81, "X-Frame-Options-Sameorigin-allow-from": 82, "X-Frame-Options-Sameorigin-deny": 83, "X-Frame-Options-Sameorigin-Disallow": 84, "X-Frame-Options-Sameorigin-Enable": 85, "X-Frame-Options-Sameorigin-allow-from": 86, "X-Frame-Options-Sameorigin-deny": 87, "X-Frame-Options-Sameorigin-Disallow": 88, "X-Frame-Options-Sameorigin-Enable": 89, "X-Frame-Options-Sameorigin-allow-from": 90, "X-Frame-Options-Sameorigin-deny": 91, "X-Frame-Options-Sameorigin-Disallow": 92, "X-Frame-Options-Sameorigin-Enable": 93, "X-Frame-Options-Sameorigin-allow-from": 94, "X-Frame-Options-Sameorigin-deny": 95, "X-Frame-Options-Sameorigin-Disallow": 96, "X-Frame-Options-Sameorigin-Enable": 97, "X-Frame-Options-Sameorigin-allow-from": 98, "X-Frame-Options-Sameorigin-deny": 99, "X-Frame-Options-Sameorigin-Disallow": 100, "X-Frame-Options-Sameorigin-Enable": 101, "X-Frame-Options-Sameorigin-allow-from": 102, "X-Frame-Options-Sameorigin-deny": 103, "X-Frame-Options-Sameorigin-Disallow": 104, "X-Frame-Options-Sameorigin-Enable": 105, "X-Frame-Options-Sameorigin-allow-from": 106, "X-Frame-Options-Sameorigin-deny": 107, "X-Frame-Options-Sameorigin-Disallow": 108, "X-Frame-Options-Sameorigin-Enable": 109, "X-Frame-Options-Sameorigin-allow-from": 110, "X-Frame-Options-Sameorigin-deny": 111, "X-Frame-Options-Sameorigin-Disallow": 112, "X-Frame-Options-Sameorigin-Enable": 113, "X-Frame-Options-Sameorigin-allow-from": 114, "X-Frame-Options-Sameorigin-deny": 115, "X-Frame-Options-Sameorigin-Disallow": 116, "X-Frame-Options-Sameorigin-Enable": 117, "X-Frame-Options-Sameorigin-allow-from": 118, "X-Frame-Options-Sameorigin-deny": 119, "X-Frame-Options-Sameorigin-Disallow": 120, "X-Frame-Options-Sameorigin-Enable": 121, "X-Frame-Options-Sameorigin-allow-from": 122, "X-Frame-Options-Sameorigin-deny": 123, "X-Frame-Options-Sameorigin-Disallow": 124, "X-Frame-Options-Sameorigin-Enable": 125, "X-Frame-Options-Sameorigin-allow-from": 126, "X-Frame-Options-Sameorigin-deny": 127, "X-Frame-Options-Sameorigin-Disallow": 128, "X-Frame-Options-Sameorigin-Enable": 129, "X-Frame-Options-Sameorigin-allow-from": 130, "X-Frame-Options-Sameorigin-deny": 131, "X-Frame-Options-Sameorigin-Disallow": 132, "X-Frame-Options-Sameorigin-Enable": 133, "X-Frame-Options-S