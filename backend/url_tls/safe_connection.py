
"""
TrustGuard AI - Safe Network Connection

Resolves a hostname once, validates every returned IP,
and connects directly to a validated IP address.

This prevents a second DNS lookup between validation
and connection (DNS rebinding protection).
"""

import ipaddress
import socket
import ssl


def open_pinned_connection(
    hostname,
    port=443,
    timeout=5,
    use_tls=True
):
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError("A valid hostname is required.")

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("Invalid port number.")

    hostname = hostname.strip().rstrip(".")

    # Resolve the hostname exactly once.
    addresses = socket.getaddrinfo(
        hostname,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM
    )

    if not addresses:
        raise socket.gaierror("No IP addresses found.")

    # Fail closed if ANY resolved address is non-global.
    for item in addresses:
        ip = item[4][0].split("%")[0]

        if not ipaddress.ip_address(ip).is_global:
            raise PermissionError(
                f"Unsafe destination IP rejected: {ip}"
            )

    errors = []

    # Connect directly using the already-validated sockaddr.
    for family, socktype, proto, _, sockaddr in addresses:
        raw_socket = socket.socket(family, socktype, proto)
        raw_socket.settimeout(timeout)

        try:
            raw_socket.connect(sockaddr)

            if use_tls:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2

                secure_socket = context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname
                )

                return secure_socket

            return raw_socket

        except Exception as error:
            raw_socket.close()
            errors.append(str(error))

    raise ConnectionError(
        "Could not connect to any validated IP address: "
        + "; ".join(errors)
    )
