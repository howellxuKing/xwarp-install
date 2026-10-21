"""Select an available high panel port without changing services or firewall rules."""
import argparse
import errno
import secrets
import socket


def check_available(value):
    handles = []
    try:
        for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
            if family == socket.AF_INET6 and not socket.has_ipv6:
                continue
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                try:
                    handle = socket.socket(family, kind)
                    handles.append(handle)
                    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                        handle.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    if family == socket.AF_INET6:
                        handle.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    handle.bind((address, value))
                except OSError as error:
                    if family == socket.AF_INET6 and error.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL):
                        continue  # IPv6 may be disabled even when Python supports it.
                    raise
    except OSError as error:
        raise ValueError("Port is occupied or unavailable; no configuration changed") from error
    finally:
        for handle in handles:
            handle.close()


def choose_port(value=None, exclude=()):
    if value is not None:
        value = int(value)
        if not 1 <= value <= 65535 or value in exclude:
            raise ValueError("Invalid or reserved panel port")
        check_available(value)
        return value
    for _ in range(100):
        candidate = 49152 + secrets.randbelow(16384)
        if candidate in exclude:
            continue
        try:
            check_available(candidate)
            return candidate
        except ValueError:
            continue
    raise ValueError("No available random port found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    try:
        print(choose_port(args.port))
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + "\n")
