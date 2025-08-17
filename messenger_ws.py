import asyncio
import json
import os
import secrets
import signal
import sqlite3
import time
from base64 import urlsafe_b64decode
from dataclasses import dataclass
from typing import Any, Dict

from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from websockets.server import serve

try:
    import uvloop

    uvloop.install()
except Exception:  # pragma: no cover
    pass

from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes as _hashes

load_dotenv()

PORT = int(os.getenv("PORT", "8765"))
DB_PATH = os.getenv("DB_PATH", "im.db")


@dataclass
class Session:
    did: str
    ws: Any
    last_seen: float


SESSIONS: Dict[str, Session] = {}


def db():
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL;")
    return con


def setup_db():
    con = db()
    con.execute(
        """CREATE TABLE IF NOT EXISTS users(
      did TEXT PRIMARY KEY,
      id_pub_jwk TEXT NOT NULL,
      dh_pub_jwk TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );"""
    )
    con.execute(
        """CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      to_did TEXT NOT NULL,
      from_did TEXT NOT NULL,
      payload BLOB NOT NULL,
      created_at INTEGER NOT NULL,
      delivered INTEGER NOT NULL DEFAULT 0
    );"""
    )
    con.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_did, delivered);"
    )
    con.commit()
    con.close()


def b64u_to_bytes(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = "=" * ((4 - len(s) % 4) % 4)
    return urlsafe_b64decode(s + pad)


def jwk_to_ec_pubkey_p256(jwk: dict):
    x = int.from_bytes(b64u_to_bytes(jwk["x"]), "big")
    y = int.from_bytes(b64u_to_bytes(jwk["y"]), "big")
    pn = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return pn.public_key()


def did_from_pubkey(pubkey) -> str:
    raw = pubkey.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    digest = _hashes.Hash(_hashes.SHA256())
    digest.update(raw)
    h = digest.finalize()
    import base64

    return "did:noda:" + base64.urlsafe_b64encode(h).decode().rstrip("=")


async def auth_flow(ws) -> str:
    hello = await ws.recv()
    msg = json.loads(hello)
    if msg.get("type") != "HELLO" or "did" not in msg:
        raise ValueError("bad HELLO")
    did = msg["did"]

    nonce = secrets.token_bytes(32).hex()
    await ws.send(json.dumps({"type": "CHALLENGE", "nonce": nonce}))

    auth = json.loads(await ws.recv())
    if auth.get("type") != "AUTH" or auth.get("did") != did:
        raise ValueError("bad AUTH")

    con = db()
    cur = con.execute("SELECT id_pub_jwk, dh_pub_jwk FROM users WHERE did=?", (did,))
    row = cur.fetchone()

    if row is None:
        id_pub_jwk = auth.get("id_pub_jwk")
        dh_pub_jwk = auth.get("dh_pub_jwk")
        if not id_pub_jwk or not dh_pub_jwk:
            raise ValueError("registration requires pub jwk")
        id_pub = jwk_to_ec_pubkey_p256(id_pub_jwk)
        expected_did = did_from_pubkey(id_pub)
        if expected_did != did:
            raise ValueError("DID mismatch")
        if not verify_ecdsa(
            id_pub, bytes.fromhex(nonce), bytes.fromhex(auth["signature"])
        ):
            raise ValueError("signature invalid")
        con.execute(
            "INSERT INTO users(did, id_pub_jwk, dh_pub_jwk, created_at) VALUES(?,?,?,?)",
            (did, json.dumps(id_pub_jwk), json.dumps(dh_pub_jwk), int(time.time())),
        )
        con.commit()
    else:
        id_pub_jwk = json.loads(row[0])
        id_pub = jwk_to_ec_pubkey_p256(id_pub_jwk)
        if not verify_ecdsa(
            id_pub, bytes.fromhex(nonce), bytes.fromhex(auth["signature"])
        ):
            raise ValueError("signature invalid")

    con.close()
    await ws.send(json.dumps({"type": "READY"}))
    return did


def verify_ecdsa(pubkey, msg_bytes: bytes, sig_bytes: bytes) -> bool:
    try:
        pubkey.verify(sig_bytes, msg_bytes, ec.ECDSA(_hashes.SHA256()))
        return True
    except Exception:
        try:
            if len(sig_bytes) == 64:
                r = int.from_bytes(sig_bytes[:32], "big")
                s = int.from_bytes(sig_bytes[32:], "big")
                der = encode_rs_to_der(r, s)
                pubkey.verify(der, msg_bytes, ec.ECDSA(_hashes.SHA256()))
                return True
        except Exception:
            return False
    return False


try:
    from asn1crypto import ecdsa

    def encode_rs_to_der(r: int, s: int) -> bytes:
        return ecdsa.ECDSASignature({"r": r, "s": s}).dump()

except Exception:

    def encode_rs_to_der(r: int, s: int) -> bytes:
        # fallback: build simple DER sequence
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

        return encode_dss_signature(r, s)


async def deliver_pending(ws, did: str):
    con = db()
    cur = con.execute(
        "SELECT id, from_did, payload FROM messages WHERE to_did=? AND delivered=0 ORDER BY id ASC",
        (did,),
    )
    rows = cur.fetchall()
    for mid, frm, payload in rows:
        await ws.send(
            json.dumps(
                {"type": "RECV", "id": mid, "from": frm, "payload": json.loads(payload)}
            )
        )
    con.close()


async def broadcast_presence():
    # send list of online DIDs to all connected sessions
    online = list(SESSIONS.keys())
    msg = json.dumps({"type": "PRESENCE", "online": online})
    for s in list(SESSIONS.values()):
        try:
            await s.ws.send(msg)
        except Exception:
            # ignore send errors; cleanup happens on disconnect
            pass


async def handle(ws):
    try:
        did = await auth_flow(ws)
    except Exception:
        await ws.close()
        return
    SESSIONS[did] = Session(did, ws, time.time())
    await deliver_pending(ws, did)
    # announce presence to all
    await broadcast_presence()

    try:
        async for raw in ws:
            msg = json.loads(raw)
            t = msg.get("type")
            if t == "PING":
                await ws.send(json.dumps({"type": "PONG", "t": msg.get("t")}))
            elif t == "SEND":
                to_did = msg["to"]
                payload = msg["payload"]
                mid = await store_or_deliver(did, to_did, payload)
                await ws.send(
                    json.dumps({"type": "ACK", "id": mid, "status": "queued"})
                )
            elif t == "RCPT":
                pass
            else:
                pass
    except (ConnectionClosedOK, ConnectionClosedError):
        pass
    finally:
        SESSIONS.pop(did, None)
        # announce presence change
        try:
            await broadcast_presence()
        except Exception:
            pass


async def store_or_deliver(frm: str, to: str, payload: dict) -> int:
    if to in SESSIONS:
        try:
            await SESSIONS[to].ws.send(
                json.dumps({"type": "RECV", "id": 0, "from": frm, "payload": payload})
            )
            return 0
        except Exception:
            pass
    con = db()
    cur = con.execute(
        "INSERT INTO messages(to_did, from_did, payload, created_at) VALUES(?,?,?,?)",
        (to, frm, json.dumps(payload), int(time.time())),
    )
    con.commit()
    mid = cur.lastrowid
    con.close()
    return mid


async def main():
    setup_db()
    stop = asyncio.Future()
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGTERM, stop.set_result, None)
    except Exception:
        pass
    async with serve(handle, "127.0.0.1", PORT, ping_interval=30, ping_timeout=30):
        await stop


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
