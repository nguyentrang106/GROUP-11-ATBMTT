from __future__ import annotations

from core.rsa_keygen import RSAPublicKey, generate_keypair
from core.signature import sign, verify
from core.step_logger import StepLogger
from core.utils import canonical_json
from pki.certificate import now
from attacks.registry import AttackResult

NAME = "A8: Chuyển tiếp lén"


def signed_part(message: bytes, to: str, t: int, bind_recipient: bool) -> bytes:
    return canonical_json({"to": to, "t": t}) + message if bind_recipient else message


def accept(env: dict, me: str, trang_pub: RSAPublicKey, bind_recipient: bool) -> tuple[bool, str]:
    if not verify(signed_part(env["m"], env["to"], env["t"], bind_recipient), env["s"], trang_pub):
        return False, "Chữ ký của Trang không hợp lệ"
    if bind_recipient and env["to"] != me:
        return False, f"Trang ký thư cho '{env['to']}', không phải '{me}' → bị chuyển tiếp lén"
    return True, "Chữ ký của Trang hợp lệ → tin rằng Trang viết thư này cho mình"


def run(logger: StepLogger | None = None, defended: bool = False, bits: int = 1024) -> AttackResult:
    log = logger if logger is not None else StepLogger()
    log.head(f"TẤN CÔNG A8: CHUYỂN TIẾP LÉN ({'CÓ' if defended else 'KHÔNG'} ký kèm người nhận)")
    trang_pub, trang_priv = generate_keypair(bits)
    m = "Anh đồng ý với đề nghị của em. Thứ Bảy gặp nhau nhé. — Trang".encode("utf-8")
    t = now()
    s = sign(signed_part(m, "thuy", t, defended), trang_priv)
    plain = "s = Sign_d_A(H(to || t || M))" if defended else "s = Sign_d_A(H(M))"
    log.log("[1] Trang ký thư rồi mã hoá gửi Thủy", plain, m.decode())
    env = {"to": "thuy", "t": t, "m": m, "s": s}
    ok_thuy, why_thuy = accept(env, "thuy", trang_pub, defended)
    log.log("[2] Thủy giải mã và kiểm tra", None, why_thuy, level="ok" if ok_thuy else "bad")

    forwarded = dict(env, to="linh") if not defended else dict(env)
    log.note("[3] Thủy giải mã, lấy nguyên (M, s) rồi mã hoá lại bằng khoá công khai của Linh")
    success, why = accept(forwarded, "linh", trang_pub, defended)
    log.log("[4] Linh mở thư", None, why, level="bad" if success else "ok")
    if defended:
        relabeled = dict(env, to="linh")
        ok2, why2 = accept(relabeled, "linh", trang_pub, defended)
        log.log("[5] Thủy sửa trường 'to' thành Linh", None, why2, level="bad" if ok2 else "ok")
        success = success or ok2

    summary = ("Linh tin Trang viết thư cho mình." if success else
               "Thất bại: danh tính người nhận nằm trong phần được ký.")
    (log.bad if success else log.ok)("[KẾT LUẬN] " + summary + " Phòng chống: ký kèm người nhận + thời gian.")
    return AttackResult(NAME, success, summary, {"defended": defended})
