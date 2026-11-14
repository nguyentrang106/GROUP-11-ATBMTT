from __future__ import annotations

import secrets

from core.hash.sha256 import sha256
from core.rsa_keygen import generate_keypair
from core.signature import sign, verify_detailed
from core.step_logger import StepLogger
from core.utils import constant_time_eq
from scenarios.registry import ScenarioResult

NAME = "S5: HMAC không chống chối bỏ được"
BLOCK = 64


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    if len(key) > BLOCK:
        key = sha256(key)
    k0 = key.ljust(BLOCK, b"\x00")
    inner = sha256(bytes(b ^ 0x36 for b in k0) + message)
    return sha256(bytes(b ^ 0x5C for b in k0) + inner)


def hmac_verify(key: bytes, message: bytes, tag: bytes) -> bool:
    return constant_time_eq(hmac_sha256(key, message), tag)


def run(logger: StepLogger | None = None, bits: int = 2048) -> ScenarioResult:
    log = logger if logger is not None else StepLogger()
    log.head("KỊCH BẢN S5: HMAC KHÔNG CHỐNG CHỐI BỎ, CHỮ KÝ RSA THÌ CÓ")

    K = secrets.token_bytes(32)
    log.note("[1] Sender và Receiver thoả thuận khoá chung K (cả hai cùng biết)", K.hex())
    m1 = "Sender đặt mua 10 máy in, tổng 30.000.000 VNĐ.".encode("utf-8")
    t1 = hmac_sha256(K, m1)
    log.log("[2] Sender gửi M1 kèm thẻ HMAC", 'T = HMAC_K(M)', f"M1 = {m1.decode()}\nT1 = {t1.hex()}")
    log.log("    Receiver kiểm tra thẻ", None, "Hợp lệ" if hmac_verify(K, m1, t1) else "Sai",
            level="ok" if hmac_verify(K, m1, t1) else "bad")

    m2 = "Sender đồng ý bồi thường cho Receiver 1.000.000.000 VNĐ.".encode("utf-8")
    t2 = hmac_sha256(K, m2)
    hmac_ambiguous = hmac_verify(K, m2, t2)
    log.log("[3] Receiver tự soạn M2 và tự tính thẻ bằng K, rồi kiện Sender", None,
            f"M2 = {m2.decode()}\nT2 = {t2.hex()}")
    log.log("    Trọng tài (được giao K) kiểm tra T2", None,
            "Thẻ HỢP LỆ — nhưng Sender và Receiver đều tạo được thẻ này, trọng tài không biết ai tạo → HMAC KHÔNG chống chối bỏ",
            level="bad" if hmac_ambiguous else "ok")

    trang_pub, trang_priv = generate_keypair(bits)
    thuy_pub, thuy_priv = generate_keypair(bits)
    s1 = sign(m1, trang_priv)
    r1 = verify_detailed(m1, s1, trang_pub)
    log.log("[4] Cùng giao dịch với chữ ký RSA: Sender ký M1 bằng d_A", None, r1.reason, level="ok" if r1.valid else "bad")
    forged = verify_detailed(m2, sign(m2, thuy_priv), trang_pub)
    log.log("[5] Receiver muốn có 'chữ ký của Sender' trên M2 nhưng chỉ có e_A, đành ký bằng d_B", None,
            f"Kiểm tra bằng e_A: {forged.reason}", level="bad" if forged.valid else "ok")
    reuse = verify_detailed(m2, s1, trang_pub)
    log.log("    Receiver gắn chữ ký thật của M1 vào M2", None, reuse.reason, level="bad" if reuse.valid else "ok")

    valid = hmac_ambiguous and r1.valid and not forged.valid and not reuse.valid
    summary = ("HMAC: ai giữ K cũng tạo được thẻ → không chống chối bỏ. RSA: chỉ người giữ d_A ký được → chống chối bỏ."
               if valid else "Kịch bản S5 không đạt.")
    (log.ok if valid else log.bad)("[KẾT LUẬN] " + summary)
    return ScenarioResult(NAME, valid, summary, {
        "hmac_thuy_forgery_accepted": hmac_ambiguous, "rsa_trang_valid": r1.valid,
        "rsa_thuy_forgery_accepted": forged.valid, "rsa_reuse_accepted": reuse.valid,
    })
