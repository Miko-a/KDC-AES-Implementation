import socket
import threading
import time

from crypto import encode_ascii_plaintext
from protocol import MAX_TEXT, log_record, protect, recv_frame, require, send_frame, unprotect


class Channel:
    def __init__(self, sock, session, role, trace=True):
        require(role in ("alice", "bob"), "Peran tidak valid")
        self.sock = sock
        self.session = session
        self.role = role
        self.peer = "bob" if role == "alice" else "alice"
        self.send_seq = 0
        self.recv_seq = 0
        self.trace = trace

    def _send(self, event, text):
        self.session.check_alive()

        require(len(encode_ascii_plaintext(text)) <= MAX_TEXT, "Pesan maksimal 4096 byte ASCII")

        record = protect(self.session.key, f"chat:{self.role}:{self.peer}", {
            "sid": self.session.sid, "sender": self.role, "recipient": self.peer,
            "seq": self.send_seq, "event": event, "text": text,
        })

        send_frame(self.sock, {"type": "chat", "record": record})
        self.send_seq += 1
        
        if self.trace:
            log_record(f"[Kirim {self.role} -> {self.peer}]", record)

    def send_text(self, text):
        self._send("message", text)

    def send_close(self):
        self._send("close", "")

    def receive(self):
        self.session.check_alive()
        frame = recv_frame(self.sock)
        require(frame.get("type") == "chat", "Menunggu pesan chat")

        record = frame["record"]
        data = unprotect(self.session.key, f"chat:{self.peer}:{self.role}", record)
        self.session.check_alive()

        require(data.get("sid") == self.session.sid, "Pesan dari sesi lain")
        require(data.get("sender") == self.peer and data.get("recipient") == self.role, "Identitas pesan salah")
        require(type(data.get("seq")) is int and data["seq"] == self.recv_seq, "Replay atau nomor urut pesan salah")
        require(data.get("event") in ("message", "close"), "Jenis event tidak dikenal")

        text = data.get("text")

        require(isinstance(text, str), "Plaintext harus berupa string")
        require(len(encode_ascii_plaintext(text)) <= MAX_TEXT, "Plaintext terlalu panjang")

        self.recv_seq += 1

        if self.trace:
            log_record(f"[Terima {self.peer} -> {self.role}]", record)

        return None if data["event"] == "close" else text


def interactive_chat(sock, session, role):
    channel = Channel(sock, session, role)
    print("\nCHAT SIAP. Ketik pesan ASCII lalu Enter. /quit untuk keluar.", flush=True)
    print("Pengiriman dan penerimaan berjalan bersamaan; tidak perlu bergiliran.", flush=True)

    def sender():
        while True:
            try:
                text = input()
            except EOFError:
                text = "/quit"
            try:
                if text == "/quit":
                    channel.send_close()
                    sock.shutdown(socket.SHUT_RDWR)
                    return
                channel.send_text(text)
            except (ValueError, TypeError) as error:
                print(f"[Input ditolak] {error}", flush=True)
            except OSError:
                return

    # Thread input daemon tidak menahan proses ketika peer menutup koneksi.
    threading.Thread(target=sender, daemon=True).start()
    try:
        while True:
            remaining = session.expires - time.time()
            require(remaining > 0, "Sesi kedaluwarsa")
            sock.settimeout(remaining)
            text = channel.receive()
            if text is None:
                print("[Selesai] Peer mengakhiri chat.", flush=True)
                break
            print(f"{channel.peer.upper()} (ASCII): {text}", flush=True)
    except (EOFError, OSError) as error:
        print(f"[Selesai] Koneksi ditutup atau masa sesi berakhir: {error}", flush=True)
    finally:
        sock.close()
