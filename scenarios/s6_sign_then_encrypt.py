from __future__ import annotations

import json
import secrets

from core.encryption import decrypt_oaep, encrypt_oaep
from core.rsa_keygen import RSAPrivateKey, RSAPublicKey, generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from core.utils import canonical_json, from_hex
from pki.certificate import fmt_time, now
from scenarios.registry import ScenarioResult

NAME = "S6: Ký rồi mã hoá (phong bì số)"


class EnvelopeError(Exception):
    pass


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as err:
        raise RuntimeError("S6 cần thư viện `cryptography` cho AES-GCM: pip install cryptography") from err
    return AESGCM


def signed_part(sender: str, to: str, t: int, message: bytes) -> bytes:
    return canonical_json({"from": sender, "to": to, "t": t}) + message


def seal(message: bytes, sender: str, sender_sign_priv: RSAPrivateKey, to: str, to_enc_pub: RSAPublicKey,
         t: int | None = None) -> dict:
    t = now() if t is None else t
    s = sign(signed_part(sender, to, t, message), sender_sign_priv)
    inner = canonical_json({"from": sender, "to": to, "t": t, "m": message.hex(), "s": s.hex()})
    return encrypt_inner(inner, to_enc_pub)


def encrypt_inner(inner: bytes, to_enc_pub: RSAPublicKey) -> dict:
    K, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    c2 = _aesgcm()(K).encrypt(nonce, inner, None)
    return {"C1": encrypt_oaep(K, to_enc_pub).hex(), "nonce": nonce.hex(), "C2": c2.hex()}


def decrypt_inner(envelope: dict, my_enc_priv: RSAPrivateKey) -> bytes:
    try:
        K = decrypt_oaep(from_hex(envelope["C1"]), my_enc_priv)
    except ValueError as err:
        raise EnvelopeError("Giải mã khoá phiên thất bại") from err
    try:
        return _aesgcm()(K).decrypt(from_hex(envelope["nonce"]), from_hex(envelope["C2"]), None)
    except Exception as err:                       # cryptography.exceptions.InvalidTag
        raise EnvelopeError("Bản mã C2 bị sửa (thẻ xác thực GCM sai)") from err


def open_envelope(envelope: dict, me: str, my_enc_priv: RSAPrivateKey,
                  sign_keys: dict[str, RSAPublicKey]) -> dict:
    inner = json.loads(decrypt_inner(envelope, my_enc_priv))
    sender, message = inner["from"], from_hex(inner["m"])
    pub = sign_keys.get(sender)
    if pub is None:
        raise EnvelopeError(f"Không có khoá công khai của người gửi '{sender}'")
    res = verify_detailed(signed_part(sender, inner["to"], inner["t"], message), from_hex(inner["s"]), pub)
    if not res.valid:
        raise EnvelopeError(f"Chữ ký của '{sender}' không hợp lệ: {res.reason}")
    if inner["to"] != me:
        raise EnvelopeError(f"Chữ ký hợp lệ nhưng '{sender}' ký thư gửi cho '{inner['to']}', không phải '{me}' "
                            "→ thư bị chuyển tiếp lén")
    return {"from": sender, "to": inner["to"], "t": inner["t"], "message": message}


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S6: KÝ RỒI MÃ HOÁ (PHONG BÌ SỐ)")
    _aesgcm()

    trang_sign_pub, trang_sign_priv = generate_keypair(bits)
    thuy_enc_pub, thuy_enc_priv = generate_keypair(bits)
    linh_enc_pub, linh_enc_priv = generate_keypair(bits)
    phuong_enc_pub, phuong_enc_priv = generate_keypair(bits)
    sign_keys = {"trang": trang_sign_pub}
    log.note("[1] Sender, Receiver, Attacker và Third Party có khoá riêng", "trang_sign, thuy_enc, linh_enc, phuong_enc")

    message = "Receiver thân mến, mật khẩu kho dữ liệu dự án là: X7#kq-2026. Sender.".encode("utf-8")
    env = seal(message, "trang", trang_sign_priv, "thuy", thuy_enc_pub)
    log.log("[2] Sender ký rồi mã hoá gửi Receiver", 's = Sign_d_A(H(to || t || M)); C₂ = AES-GCM_K(M || s); C₁ = RSA-Enc_e_B(K)',
            f"C1 = {env['C1'][:48]}…\nC2 = {env['C2'][:48]}… ({len(env['C2']) // 2} byte)")
    log.log("    Attacker nghe lén chỉ thấy C1, nonce, C2", None,
            f"Bản rõ có xuất hiện trong gói tin? {message.hex() in json.dumps(env)}", level="ok")

    try:
        opened = open_envelope(env, "thuy", thuy_enc_priv, sign_keys)
        thuy_ok = opened["message"] == message
        log.log("[3] Receiver giải mã K, C2 và kiểm tra chữ ký của Sender", None,
                f"Người gửi: {opened['from']}, gửi cho: {opened['to']}, lúc {fmt_time(opened['t'])}\n"
                f"M = {opened['message'].decode()}", level="ok" if thuy_ok else "bad")
    except EnvelopeError as err:
        thuy_ok = False
        log.bad("[3] Receiver không mở được phong bì", str(err))

    def attempt(title: str, fn) -> bool:
        try:
            fn()
            log.bad(title, "Mở được — lỗi!")
            return True
        except EnvelopeError as err:
            log.ok(title, f"Bị chặn: {err}")
            return False

    phuong_ok = attempt("[4] Attacker mở phong bì bằng khoá riêng của mình",
                         lambda: open_envelope(env, "phuong", phuong_enc_priv, sign_keys))
    bad = dict(env)
    c2 = bytearray(from_hex(env["C2"]))
    c2[len(c2) // 2] ^= 0x01
    bad["C2"] = c2.hex()
    tamper_ok = attempt("[5] Attacker lật 1 bit trong C2 rồi chuyển cho Receiver",
                        lambda: open_envelope(bad, "thuy", thuy_enc_priv, sign_keys))
    forwarded = encrypt_inner(decrypt_inner(env, thuy_enc_priv), linh_enc_pub)
    forward_ok = attempt("[6] Receiver chuyển tiếp (M, s) cho Third Party",
                         lambda: open_envelope(forwarded, "linh", linh_enc_priv, sign_keys))

    valid = thuy_ok and not phuong_ok and not tamper_ok and not forward_ok
    summary = ("Phong bì số cho cả bảo mật (chỉ Receiver đọc được) lẫn chứng thực; ký kèm người nhận chặn chuyển tiếp lén."
               if valid else "Kịch bản S6 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "thuy_opens": thuy_ok, "phuong_opens": phuong_ok, "tampered_accepted": tamper_ok,
        "forward_accepted": forward_ok,
    })
