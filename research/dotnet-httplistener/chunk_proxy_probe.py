#!/usr/bin/env python3
import socket

TARGETS = [
    ("DIRECT", 18081),
    ("NGINX", 18080),
    ("HAPROXY", 18082),
    ("APACHE", 18083),
    ("VARNISH", 18090),
]

CASES = [
    ("VALID_EXTENSION", b"5;foo=bar"),
    ("UNTERMINATED_QUOTED_VALUE", b'5;foo="unterminated'),
    ("SPACE_IN_UNQUOTED_VALUE", b"5;foo=bar baz"),
    ("TAB_AFTER_SEMICOLON", b"5;\tfoo=bar"),
    ("CONTROL_IN_EXTENSION", b"5;foo=\x01bar"),
]

def send(port, chunk_line):
    request = (
        b"POST /chunk HTTP/1.1\r\n"
        + b"Host: public.test\r\n"
        + b"Transfer-Encoding: chunked\r\n"
        + b"Connection: close\r\n"
        + b"\r\n"
        + chunk_line + b"\r\n"
        + b"Hello\r\n"
        + b"0\r\n"
        + b"\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(request)
        s.settimeout(5)
        chunks=[]
        try:
            while True:
                b=s.recv(8192)
                if not b: break
                chunks.append(b)
        except socket.timeout:
            pass
    return b"".join(chunks).decode("latin1", "replace")

for target, port in TARGETS:
    for name, line in CASES:
        try:
            response=send(port, line)
            first=response.splitlines()[0] if response else "<NO_RESPONSE>"
            body=response.split("\r\n\r\n",1)[1].strip() if "\r\n\r\n" in response else ""
            print(f"CHUNK_PROXY target={target} case={name} first={first!r} body={body!r}")
        except Exception as e:
            print(f"CHUNK_PROXY target={target} case={name} error={type(e).__name__}:{e}")
