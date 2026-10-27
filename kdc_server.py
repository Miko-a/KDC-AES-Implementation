import argparse
import socket
import time

from crypto import validate_ascii_key
from protocol import (
    HANDSHAKE_TIMEOUT, Session, expect_step, is_nonce,
    load_network, log_record, new_session_key, nonce, protect, read_key,
    recv_frame, require, send_frame,
)


class KDC:
    def __init__(self, keys, network, ttl=300):
        for role in ("alice", "bob"):
            validate_ascii_key(keys[role], f"Master key {role}")

        require(keys["alice"] != keys["bob"], "Gunakan master key berbeda untuk Alice dan Bob")
        require(type(ttl) is int and 30 <= ttl <= 3600, "TTL harus 30-3600 detik")

        self.keys = dict(keys)
        self.network = network
        self.ttl = ttl
        self.seen = {}

    def issue(self, request, peer_ip):
        expect_step(request, 1)

        require(request.get("alice") == "alice" and request.get("bob") == "bob", "Identitas tidak dikenal")
        require(peer_ip == self.network["alice"]["ip"], "IP peminta bukan IP Alice")
        require(is_nonce(request.get("n1")), "N1 tidak valid")

        now = int(time.time())
        self.seen = {item: expiry for item, expiry in self.seen.items() if expiry > now}

        require(request["n1"] not in self.seen, "N1 permintaan sudah digunakan")

        self.seen[request["n1"]] = now + self.ttl

        session = Session(new_session_key(), nonce(), "alice", "bob", now, now + self.ttl)

        alice_part = protect(self.keys["alice"], "kdc-reply", {
            **session.payload(), "n1": request["n1"],
        })

        ticket = protect(self.keys["bob"], "bob-ticket", session.payload())

        print(f"[1] Alice ({peer_ip}) meminta sesi dengan Bob; N1={request['n1']}", flush=True)

        log_record("[2] KDC -> Alice: bagian Alice", alice_part)
        log_record("[2] KDC -> Alice: tiket untuk Bob", ticket)

        return {"step": 2, "alice_part": alice_part, "ticket": ticket}


def handle_request(sock, peer_ip, kdc):
    sock.settimeout(HANDSHAKE_TIMEOUT)
    try:
        request = recv_frame(sock)
        send_frame(sock, kdc.issue(request, peer_ip))
    except (ValueError, TypeError, KeyError, OSError, EOFError) as error:
        print(f"[Ditolak] {peer_ip}: {error}", flush=True)
        try:
            send_frame(sock, {"type": "error"})
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ttl", type=int, default=300)
    args = parser.parse_args()
    network = load_network()
    keys = {role: read_key(f"Master key {role.upper()}") for role in ("alice", "bob")}
    kdc = KDC(keys, network, args.ttl)
    address = (network["kdc"]["ip"], network["kdc"]["port"])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(address)
        listener.listen(1)

        print(f"KDC siap pada {address[0]}:{address[1]}; TTL={args.ttl} detik. Ctrl+C untuk berhenti.", flush=True)

        try:
            while True:
                sock, peer = listener.accept()
                with sock:
                    handle_request(sock, peer[0], kdc)
        except KeyboardInterrupt:
            print("\nKDC dihentikan.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError) as error:
        raise SystemExit(f"KDC gagal: {error}")
