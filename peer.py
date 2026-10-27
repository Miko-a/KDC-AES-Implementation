import secrets
import socket
import time

from chat import interactive_chat
from protocol import (
    HANDSHAKE_TIMEOUT, Session, connect,
    expect_step, load_network, log_record, nonce, protect, read_key,
    recv_frame, require, send_frame, unprotect,
)


def initiate(key_alice, network, source_ip=None):
    n1 = nonce()
    request = {"step": 1, "alice": "alice", "bob": "bob", "n1": n1}

    with connect(network["kdc"]["ip"], network["kdc"]["port"], source_ip) as kdc_sock:
        print(f"[1] Alice -> KDC: IDA=alice, IDB=bob, N1={n1}", flush=True)
        send_frame(kdc_sock, request)
        reply = recv_frame(kdc_sock)

    expect_step(reply, 2)

    payload = unprotect(key_alice, "kdc-reply", reply["alice_part"])
    require(payload.get("n1") == n1, "N1 balasan KDC tidak cocok")

    session = Session.from_payload(payload)
    log_record("[2] Balasan KDC untuk Alice", reply["alice_part"])

    sock = connect(network["bob"]["ip"], network["bob"]["port"], source_ip)
    try:
        # Alice meneruskan tiket apa adanya; Alice tidak memiliki KB.
        send_frame(sock, {"step": 3, "ticket": reply["ticket"]})
        log_record("[3] Alice -> Bob: tiket", reply["ticket"])

        challenge = recv_frame(sock)
        expect_step(challenge, 4)
        data = unprotect(session.key, "bob-challenge", challenge["record"])
        require(data.get("sid") == session.sid, "Tantangan dari sesi lain")
        n2 = data.get("n2")

        require(
            isinstance(n2, str) and n2.isascii() and n2.isdecimal()
            and 1 <= len(n2) <= 39,
            "N2 tidak valid",
        )

        value = int(n2)
        require(0 < value < (1 << 128), "N2 di luar rentang")
        log_record("[4] Bob -> Alice: tantangan N2", challenge["record"])

        # Fungsi f(N2) yang disepakati dalam implementasi ini adalah N2 - 1.
        response = protect(session.key, "alice-response", {
            "sid": session.sid, "f_n2": str(value - 1),
        })

        send_frame(sock, {"step": 5, "record": response})
        log_record("[5] Alice -> Bob: f(N2) = N2 - 1", response)

        session.check_alive()
        return sock, session
    
    except BaseException:
        sock.close()
        raise


def respond(sock, key_bob, network, peer_ip, used_tickets):
    require(peer_ip == network["alice"]["ip"], "Koneksi bukan dari IP Alice")
    sock.settimeout(HANDSHAKE_TIMEOUT)

    frame = recv_frame(sock)
    expect_step(frame, 3)
    session = Session.from_payload(unprotect(key_bob, "bob-ticket", frame["ticket"]))
    now = time.time()

    for sid in list(used_tickets):
        if used_tickets[sid] <= now:
            del used_tickets[sid]

    require(session.sid not in used_tickets, "Tiket sesi sudah digunakan")
    log_record("[3] Bob menerima tiket dari Alice", frame["ticket"])

    n2 = secrets.randbelow((1 << 128) - 1) + 1
    challenge = protect(session.key, "bob-challenge", {"sid": session.sid, "n2": str(n2)})
    send_frame(sock, {"step": 4, "record": challenge})
    log_record("[4] Bob -> Alice: tantangan N2", challenge)

    response = recv_frame(sock)
    expect_step(response, 5)
    data = unprotect(session.key, "alice-response", response["record"])
    require(data.get("sid") == session.sid, "Respons dari sesi lain")
    require(data.get("f_n2") == str(n2 - 1), "Jawaban f(N2) salah")

    session.check_alive()

    # Ditandai setelah pembuktian key berhasil; Bob melayani satu sesi per proses.
    used_tickets[session.sid] = session.expires
    log_record("[5] Bob memverifikasi f(N2) = N2 - 1", response["record"])

    return session


def main(role):
    sock = None
    try:
        network = load_network()
        key = read_key(f"Master key {role.upper()}")
        if role == "alice":
            sock, session = initiate(key, network)
        else:
            used_tickets = {}
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("0.0.0.0", network["bob"]["port"]))
                listener.listen(5)
                print(
                    f"Bob siap pada {network['bob']['ip']}:{network['bob']['port']}; "
                    "menunggu Alice. Ctrl+C untuk berhenti.", flush=True,
                )
                while True:
                    sock, address = listener.accept()
                    try:
                        session = respond(sock, key, network, address[0], used_tickets)
                        break
                    except (ValueError, TypeError, KeyError, OSError, EOFError) as error:
                        print(f"[Ditolak] {error}", flush=True)
                        try:
                            send_frame(sock, {"type": "error"})
                        except OSError:
                            pass
                        sock.close()
                        sock = None
        interactive_chat(sock, session, role)
    except KeyboardInterrupt:
        print("\nProgram dihentikan.", flush=True)
    except (ValueError, TypeError, KeyError, OSError, EOFError) as error:
        print(f"[Gagal] {error}", flush=True)
        print("Periksa key, IP pada network.json, koneksi Tailscale, dan urutan KDC -> Bob -> Alice.", flush=True)
        raise SystemExit(1)
    finally:
        if sock is not None:
            sock.close()


if __name__ == "__main__":
    raise SystemExit("Jalankan python alice.py atau python bob.py")
