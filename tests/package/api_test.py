"""Tests of the connectsensors server APIs a network server builds on: typed state,
persisting and restoring JoinResponder, UplinkCollector and CommandAcks, the SENT-gated stall count,
the exported proxy and sensor sides, and the spec 09 federation helpers.

check.sh runs it against the installed wheel and type-checks it with mypy --strict
--warn-unreachable, which also catches state attributes typed as always None.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable

import connectsensors as cs

K_ROOT = bytes(range(16))
DEV_EUI = bytes.fromhex("70b3d57ed0000001")
SERVER_PRIV = bytes([0x11] * 32)
T0 = 1_780_000_000


def sensor_priv(n: int) -> bytes:
    return bytes([0x40 + n] * 32)


def typed_state() -> None:
    # Fresh instances: mypy keeps an "is None" narrowing across later method calls.
    assert cs.ServerLink(lambda: 7).boot_id is None
    assert cs.ProxyLink(0x1234).last_requested_ms is None
    assert cs.SensorPairing(K_ROOT, DEV_EUI).k_session is None
    assert cs.SensorPairing(K_ROOT, DEV_EUI).joining is None
    assert cs.JoinResponder(K_ROOT, DEV_EUI).pending is None

    # Each line after an "is not None" is unreachable to mypy if the attribute is
    # inferred as always None.
    link = cs.ServerLink(lambda: 7)
    sensor = cs.SensorPairing(K_ROOT, DEV_EUI)
    srv = cs.JoinResponder(K_ROOT, DEV_EUI)
    key, pid, boot = bytes(16), bytes.fromhex("348518fffe000001"), 0x1234
    body = cs.hello_body(cs.CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 1, [0] * 7, 5, "t", 7)
    assert link.receive(cs.open_envelope(key, cs.envelope(key, cs.M_HELLO, pid, boot, 1, body)), 0) \
        == {"result": "hello_request", "nonce": 7}
    assert link.receive(cs.open_envelope(key, cs.envelope(key, cs.M_HELLO, pid, boot, 2, body)), 1) \
        == {"result": "switched"}
    assert link.boot_id is not None
    boot_id: int = link.boot_id
    assert boot_id == boot

    sensor.join(1, sensor_priv(0))
    assert sensor.joining is not None
    r = srv.join(sensor.join(1, sensor_priv(0)), SERVER_PRIV, T0)
    assert srv.pending is not None
    pending: cs.PendingExchange = srv.pending
    assert sensor.downlink(r["frame"]) == "accept"
    assert sensor.k_session is not None
    k_session: bytes = sensor.k_session
    assert k_session == pending.k_session == r["k_session"]
    print("ok   typed state")


def persist_pending_exchange() -> None:
    sensor = cs.SensorPairing(K_ROOT, DEV_EUI)
    join = sensor.join(5, sensor_priv(1))
    srv = cs.JoinResponder(K_ROOT, DEV_EUI, 41)
    first = srv.join(join, SERVER_PRIV, T0)
    assert first["action"] == "new_exchange" and srv.root_fcnt_down == 42
    assert srv.pending is not None
    stored = json.dumps({"root_fcnt_down": srv.root_fcnt_down, "pending": srv.pending.to_dict()})

    # A restart: the retransmitted JOIN gets the identical frame and k_session back.
    d = json.loads(stored)
    pending = cs.PendingExchange.from_dict(d["pending"])
    assert pending == srv.pending
    restored = cs.JoinResponder(K_ROOT, DEV_EUI, d["root_fcnt_down"], pending)
    again = restored.join(join, None, None)
    assert again["action"] == "resend"
    assert (again["frame"], again["k_session"]) == (first["frame"], first["k_session"])
    assert restored.root_fcnt_down == 42
    assert sensor.downlink(again["frame"]) == "accept" and sensor.k_session == first["k_session"]

    # A new JOIN after the restart takes the next root counter value.
    nxt = restored.join(sensor.join(6, sensor_priv(2)), SERVER_PRIV, T0 + 60)
    assert nxt["action"] == "new_exchange" and restored.root_fcnt_down == 43
    restored.paired()
    assert restored.pending is None

    # A new exchange without server_priv and server_time cannot be built.
    try:
        restored.join(sensor.join(7, sensor_priv(3)), None, None)
    except ValueError:
        pass
    else:
        raise AssertionError("a new exchange was built without server_priv")
    print("ok   pending exchange persisted and restored")


def persist_uplink_counter() -> None:
    def frame(fcnt: int) -> bytes:
        keys = cs.keys_from(K_ROOT, DEV_EUI)
        return cs.seal(keys, cs.T_DATA, cs.normal_tag(keys.k_dev_tag, 0), fcnt, b"\x00")

    col = cs.UplinkCollector(3)
    assert col.receive(frame(10), 0)["counter"] == "accept"
    assert col.receive(frame(8), 10_000)["counter"] == "accept_late"
    last, seen = col.counter.last, sorted(col.counter.seen)
    assert (last, seen) == (10, [3, 8])

    restored = cs.UplinkCollector(last, seen)
    assert restored.receive(frame(8), 0)["counter"] == "duplicate"
    assert restored.receive(frame(3), 10_000)["counter"] == "duplicate"
    assert restored.receive(frame(9), 20_000)["counter"] == "accept_late"
    assert restored.receive(frame(10), 30_000)["counter"] == "duplicate"

    # UplinkCounter alone; values outside the reorder window below last are dropped.
    ctr = cs.UplinkCounter(40, [39, 30, 24, 41])
    assert ctr.seen == {39, 30}
    assert [ctr.offer(f) for f in (39, 30, 38, 24)] == ["duplicate", "duplicate", "accept_late", "too_old"]
    print("ok   uplink counter persisted and restored")


def command_acks() -> None:
    hb = cs.command(cs.CMD_SET_HEARTBEAT, (60).to_bytes(2, "big"))
    leave = cs.command(cs.CMD_LEAVE)
    acks = cs.CommandAcks[bytes]()
    assert acks.uplink(20, "accept", False) == []
    assert acks.downlink(20, [hb]) == [hb]
    assert acks.uplink(18, "accept_late", True) == []  # older frame: settles nothing
    record = (acks.reply_to, list(acks.awaiting), acks.last_fcnt)
    assert record == (20, [hb], 20)

    restored = cs.CommandAcks[bytes](*record)
    try:
        restored.downlink(19, [leave])
        raise AssertionError("commands on an answer to a late arrival")
    except ValueError:
        pass
    assert restored.uplink(21, "accept", True) == [hb]
    assert restored.reply_to is None and restored.awaiting == []
    print("ok   CommandAcks")


def stall_after_sent() -> None:
    sensor = cs.SensorPairing(K_ROOT, DEV_EUI)
    join_a = sensor.join(1, sensor_priv(4))

    # Default: every retransmission counts, the third is the stall.
    srv = cs.JoinResponder(K_ROOT, DEV_EUI)
    srv.join(join_a, SERVER_PRIV, T0)
    assert [srv.join(join_a, None, None)["stalled"] for _ in range(3)] == [False, False, True]

    # count_after_sent: retransmissions before the KEY_EXCHANGE was reported SENT
    # (it never went out, for example TOO_LATE) do not count.
    srv = cs.JoinResponder(K_ROOT, DEV_EUI, count_after_sent=True)
    first = srv.join(join_a, SERVER_PRIV, T0)
    assert [srv.join(join_a, None, None)["stalled"] for _ in range(4)] == [False] * 4
    assert srv.pending is not None and (srv.pending.retransmissions, srv.pending.sent) == (0, False)

    # It survives a restart unsent, and SENT for another frame changes nothing.
    pending = cs.PendingExchange.from_dict(json.loads(json.dumps(srv.pending.to_dict())))
    srv = cs.JoinResponder(K_ROOT, DEV_EUI, srv.root_fcnt_down, pending, count_after_sent=True)
    assert srv.sent(first["frame"][:-1] + bytes([first["frame"][-1] ^ 1])) is False
    assert srv.join(join_a, None, None)["stalled"] is False
    assert srv.sent(first["frame"]) is True
    assert [srv.join(join_a, None, None)["stalled"] for _ in range(3)] == [False, False, True]

    # A new JOIN starts the count again and waits for its own SENT.
    join_b = sensor.join(2, sensor_priv(5))
    second = srv.join(join_b, SERVER_PRIV, T0 + 120)
    assert srv.sent(first["frame"]) is False
    assert [srv.join(join_b, None, None)["stalled"] for _ in range(3)] == [False] * 3
    srv.sent(second["frame"])
    assert [srv.join(join_b, None, None)["stalled"] for _ in range(3)] == [False, False, True]

    # A record stored before "sent" existed counts from the start, as 0.2.0 did.
    old = {k: v for k, v in pending.to_dict().items() if k != "sent"}
    assert cs.PendingExchange.from_dict(old).sent is True
    assert cs.JOIN_STALL_RETRANSMISSIONS == 3
    print("ok   stall counted after SENT")


def proxy_side() -> None:
    # A server's SERVER_STATUS opens and is accepted on the exported proxy side.
    key, pid, boot = bytes(16), bytes.fromhex("348518fffe000001"), 99
    proxy = cs.ProxyLink(boot)
    hello = cs.open_envelope(key, cs.envelope(key, cs.M_HELLO, pid, boot, 1, cs.hello_body(
        cs.CAP_DOWNLINK, "US915", 918_500_000, 9, 500, 1, [0] * 7, 5, "t")))
    proxy.sent(hello, 0)
    status = cs.envelope(key, cs.M_SERVER_STATUS, pid, boot, 1, cs.server_status_body(T0, 1))
    assert proxy.receive(cs.open_envelope(key, status), 10) == {"result": "accepted"}
    assert proxy.receive(cs.open_envelope(key, status), 20) == {"result": "ignored"}
    print("ok   ProxyLink")


def raises_value_error(f: Callable[[], object]) -> bool:
    try:
        f()
    except ValueError:
        return True
    return False


def federation() -> None:
    # Deterministic CBOR round trip; a non-shortest integer is rejected.
    value = [0, 23, 24, 65536, -1, -500, b"", b"\x01\x02", [1, [b"x"]]]
    assert cs.uncbor(cs.cbor(value)) == value
    assert cs.cbor(24) == b"\x18\x18" and raises_value_error(lambda: cs.uncbor(b"\x18\x17"))
    assert raises_value_error(lambda: cs.cbor(True))

    # Every message type has a schema, and the signed ones are the client's after AUTH.
    types = [cs.MB_HELLO, cs.MB_AUTH, cs.MB_REGISTER, cs.MB_WITHDRAW, cs.MB_REQUEST, cs.MB_PING,
             cs.MB_PUBLISH, cs.MB_RESULT, cs.MB_PONG, cs.MB_GREETING, cs.MB_WELCOME, cs.MB_REGISTERED,
             cs.MB_PONG_S, cs.MB_PING_S, cs.MB_DELIVER, cs.MB_FORWARD, cs.MB_RESULT_S, cs.MB_ERROR]
    assert sorted(types) == sorted(cs.MB_SCHEMA) and len(set(types)) == 18
    assert cs.MB_SIGNED == {cs.MB_REGISTER, cs.MB_WITHDRAW, cs.MB_REQUEST, cs.MB_PING, cs.MB_PUBLISH,
                            cs.MB_RESULT, cs.MB_PONG}
    assert cs.MB_ERRORS[0] == "OK" and cs.TX_RESULTS[0] == "SENT"

    # Handshake: the server signs the greeting, the client its auth.
    server_seed, client_seed, other_seed = bytes([1] * 32), bytes([2] * 32), bytes([3] * 32)
    server_pub, client_pub = cs.ed25519_pub(server_seed), cs.ed25519_pub(client_seed)
    sid = cs.server_id_of(server_pub)
    assert len(sid) == 32
    nonce_c, nonce_s = bytes(range(16)), bytes(range(16, 32))
    hello = cs.cbor([cs.MB_HELLO, cs.MB_VERSION, nonce_c])
    assert cs.open_hello(hello) == cs.mb_decode(hello) == [cs.MB_HELLO, cs.MB_VERSION, nonce_c]
    assert raises_value_error(lambda: cs.open_hello(cs.cbor([cs.MB_HELLO, cs.MB_VERSION + 1, nonce_c])))
    assert raises_value_error(lambda: cs.mb_decode(b"\x00" * (cs.MB_MAX_MESSAGE + 1)))
    greeting = cs.greeting_msg("mailbox.example", nonce_c, nonce_s, 7)
    sig = cs.ed_sign(server_seed, greeting)
    assert cs.ed_verify_error(server_pub, greeting, sig) is None
    assert cs.ed_verify_error(server_pub, cs.greeting_msg("other.example", nonce_c, nonce_s, 7), sig) \
        == "bad signature"
    auth = cs.auth_msg(sid, nonce_c, nonce_s, client_pub)
    assert cs.ed_verify_error(client_pub, auth, cs.ed_sign(client_seed, auth)) is None
    pseud = cs.pseudonym(sid, client_pub)
    assert len(pseud) == 8 and pseud != cs.pseudonym(sid, cs.ed25519_pub(other_seed))

    # Signed messages: open_signed checks the signature and the sequence number.
    ping = cs.signed(client_seed, sid, nonce_s, [cs.MB_PING, 1])
    assert cs.open_signed(ping, client_pub, sid, nonce_s, 1)[:2] == [cs.MB_PING, 1]
    assert raises_value_error(lambda: cs.open_signed(ping, client_pub, sid, nonce_s, 2))
    assert raises_value_error(lambda: cs.open_signed(ping, client_pub, sid, bytes(16), 1))

    # Registration: an entry verifies only for the server and owner it was made for.
    keys = cs.keys_from(K_ROOT, DEV_EUI)
    tag_seed = cs.tag_seed(keys.k_dev_tag, b"\x00" * 4)
    entry = cs.reg_entry(tag_seed, sid, client_pub, T0 + 3600)
    assert entry[0] == cs.ed25519_pub(tag_seed)
    assert cs.check_entry(entry, sid, client_pub, T0) == "OK"
    assert cs.check_entry(entry, sid, cs.ed25519_pub(other_seed), T0) == "BAD_PROOF"
    assert cs.check_entry(entry, sid, client_pub, T0 + 3600) == "BAD_EXPIRES"
    assert cs.sync_window(1, 0, 15) == (0, 2)

    # Timing: RX2 is reachable on short round trips, not without both or after a wait.
    assert cs.federated_request_ok(100, 200, 200, 0)
    assert not cs.federated_request_ok(100, 200, None, 0)
    assert not cs.federated_request_ok(100, cs.RTT_UNKNOWN, 200, 0)
    assert not cs.federated_request_ok(100, 200, 200, 2000)
    assert cs.RXF_TS_UNCERTAIN == 0x01 and cs.RXF_DOWNLINK == 0x02

    # One request per transmission, heard by two publishers.
    frame = cs.seal(keys, cs.T_DATA_CONFIRMED, cs.normal_tag(keys.k_dev_tag, 0), 5, b"\x00")
    assert len(cs.frame_key(frame)) == 8
    ref_a, ref_b = b"A" * 8, b"B" * 8
    tx = cs.MailboxTransmissions()
    assert tx.publish(0, frame, "a", [(ref_a, 0)]) == (1, "new")
    assert tx.publish(10, frame, "b", [(ref_b, 0)]) == (1, "copy")
    assert tx.publish(20, frame, "b", [(ref_a, 0)]) == (0, "BAD_FRAME")
    assert tx.request(30, ref_a) == "forward"
    assert tx.request(40, ref_b) == "ALREADY_ANSWERED"
    assert tx.request(30 + cs.FORWARD_TIMEOUT_MS, ref_b) == "forward"
    assert tx.result(40 + cs.FORWARD_TIMEOUT_MS, "a", ref_a, 0) == "ignored"  # timed out
    assert tx.result(40 + cs.FORWARD_TIMEOUT_MS, "b", ref_b, 0) == "accepted"
    assert tx.check_request(10 + cs.RX_REF_MS + 1, ref_b) == "UNKNOWN_RX_REF"
    print("ok   09 federation")


def main() -> int:
    typed_state()
    persist_pending_exchange()
    persist_uplink_counter()
    command_acks()
    stall_after_sent()
    proxy_side()
    federation()
    print(f"connectsensors {cs.__version__}: API tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
