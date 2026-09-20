#!/usr/bin/env python3
import socket, time

TARGETS = [
    ("DIRECT", 18081),
    ("NGINX", 18080),
    ("HAPROXY", 18082),
]

CASES = [
    ("CONTROL", lambda p: (
        "GET /control HTTP/1.1\r\n"
        "Host: public.test\r\n"
        "Connection: close\r\n\r\n"
    )),
    ("DUP_PUBLIC_ADMIN", lambda p: (
        "GET /dup-public-admin HTTP/1.1\r\n"
        "Host: public.test\r\n"
        "Host: admin.test\r\n"
        "Connection: close\r\n\r\n"
    )),
    ("DUP_ADMIN_PUBLIC", lambda p: (
        "GET /dup-admin-public HTTP/1.1\r\n"
        "Host: admin.test\r\n"
        "Host: public.test\r\n"
        "Connection: close\r\n\r\n"
    )),
    ("MIXED_LF_PUBLIC_ADMIN", lambda p: (
        "GET /mixed HTTP/1.1\r\n"
        "Host: public.test\n"
        "Host: admin.test\r\n"
        "Connection: close\r\n\r\n"
    )),
]

def send(port, raw):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall(raw.encode("ascii"))
        s.shutdown(socket.SHUT_WR)
        chunks=[]
        s.settimeout(3)
        try:
            while True:
                b=s.recv(8192)
                if not b: break
                chunks.append(b)
        except socket.timeout:
            pass
    return b"".join(chunks).decode("latin1", "replace")

for target, port in TARGETS:
    for name, make in CASES:
        try:
            response=send(port, make(port))
            first=response.splitlines()[0] if response else "<NO_RESPONSE>"
            body=response.split("\r\n\r\n",1)[1].strip() if "\r\n\r\n" in response else ""
            print(f"PROXY_CASE target={target} case={name} first={first!r} body={body!r}")
        except Exception as e:
            print(f"PROXY_CASE target={target} case={name} error={type(e).__name__}:{e}")
