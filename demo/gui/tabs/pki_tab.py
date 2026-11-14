from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QSplitter, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from core.rsa_keygen import generate_keypair
from core.signature import SignatureBundle, sign
from demo.gui.widgets import common
from demo.gui.widgets.common import SAMPLE, OutputBox, button, glass, hbox
from demo.gui.widgets.result_badge import ResultBadge
from demo.gui.widgets.presentation import participant_text
from pki.ca import CertificateAuthority
from pki.certificate import Certificate, fmt_time
from pki.chain_verify import verify_chain
from pki.timestamp import TimestampAuthority
from scenarios.s3_non_repudiation_contract import arbitrate

FALLBACK_CONTRACT = "HỢP ĐỒNG MUA BÁN — Tổng giá trị: 2.000.000.000 VNĐ".encode("utf-8")


class PKITab(QWidget):
    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.root: CertificateAuthority | None = None
        self.inter: CertificateAuthority | None = None
        self.tsa: TimestampAuthority | None = None
        self.people: dict[str, tuple] = {}           # tên -> ((pub, priv), cert)
        self.bundle: SignatureBundle | None = None
        path = SAMPLE / "messages" / "contract.txt"
        self.contract = path.read_bytes() if path.is_file() else FALLBACK_CONTRACT
        lay = QVBoxLayout(self)

        self.bits = QComboBox()
        self.bits.addItems(("1024", "2048", "3072"))
        cert_box = QGroupBox("1. Chứng thực khoá công khai (CA cấp và kiểm tra chứng chỉ)")
        cert_box.setObjectName("CertGroup")
        cert_grid = QGridLayout(cert_box)
        cert_actions = [
            ("1.1. Tạo Root CA + Intermediate CA + TSA", self.create_cas),
            ("1.2. Cấp chứng chỉ cho Sender", lambda: self.issue("trang")),
            ("1.3. Cấp chứng chỉ cho Receiver", lambda: self.issue("thuy")),
            ("1.4. Kiểm tra chuỗi chứng chỉ đang chọn", self.verify_selected),
            ("1.5. Thu hồi chứng chỉ đang chọn", self.revoke_selected),
        ]
        for i, (text, slot) in enumerate(cert_actions):
            cert_grid.addWidget(button(text, slot), i // 3, i % 3)

        nonrep_box = QGroupBox("2. Chống chối bỏ (ký + dấu thời gian, Third Party phân xử)")
        nonrep_box.setObjectName("NonRepGroup")
        nonrep_grid = QGridLayout(nonrep_box)
        nonrep_actions = [
            ("2.1. Sender ký hợp đồng + dấu thời gian", self.trang_signs),
            ("2.2. Sender chối bỏ → Third Party phân xử", self.verify_signed),
            ("2.3. Attacker sửa hợp đồng → Third Party phân xử", self.tamper_contract),
        ]
        for i, (text, slot) in enumerate(nonrep_actions):
            b = button(text, slot)
            b.setProperty("variant", "nonrep")
            nonrep_grid.addWidget(b, 0, i)

        lay.addLayout(hbox(QLabel("Độ dài khoá của CA và người dùng:"), self.bits, None))
        lay.addWidget(cert_box)
        lay.addWidget(nonrep_box)
        self.badge = ResultBadge()
        lay.addWidget(self.badge)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = glass(QTreeWidget())
        self.tree.setHeaderLabels(("Chủ thể", "Serial", "Hiệu lực tới", "Trạng thái"))
        self.tree.setColumnWidth(0, 220)
        self.tree.itemSelectionChanged.connect(self.show_selected)
        box = QGroupBox("Chuỗi chứng chỉ")
        QHBoxLayout(box).addWidget(self.tree)
        split.addWidget(box)
        self.out = OutputBox()
        box2 = QGroupBox("Chi tiết")
        QVBoxLayout(box2).addWidget(self.out)
        split.addWidget(box2)
        split.setSizes([520, 560])
        lay.addWidget(split, 1)
    def _need_cas(self) -> bool:
        if self.root is None:
            common.show_info(self, "Chưa có CA", "Bấm '1.1. Tạo Root CA + Intermediate CA + TSA' trước.")
            return False
        return True

    def _crls(self):
        return [self.root.publish_crl(), self.inter.publish_crl()]

    def _status(self, cert: Certificate) -> tuple[bool, str]:
        res = verify_chain(cert, [self.inter.certificate], [self.root.certificate], self._crls())
        return res.valid, res.reason

    def refresh(self) -> None:
        self.tree.clear()
        if self.root is None:
            return

        def node(parent, cert: Certificate) -> QTreeWidgetItem:
            ok, reason = self._status(cert)
            item = QTreeWidgetItem([participant_text(cert.subject), str(cert.serial)[:10] + "…", fmt_time(cert.not_after)[:10],
                                    "Hợp lệ" if ok else "Bị thu hồi" if "thu hồi" in reason else "Lỗi"])
            item.setForeground(3, Qt.GlobalColor.darkGreen if ok else Qt.GlobalColor.red)
            item.setData(0, Qt.ItemDataRole.UserRole, cert)
            (parent.addChild if isinstance(parent, QTreeWidgetItem) else parent.addTopLevelItem)(item)
            return item

        r = node(self.tree, self.root.certificate)
        i = node(r, self.inter.certificate)
        for _, cert in self.people.values():
            node(i, cert)
        node(r, self.tsa.certificate)
        self.tree.expandAll()

    def _selected(self) -> Certificate | None:
        items = self.tree.selectedItems()
        return items[0].data(0, Qt.ItemDataRole.UserRole) if items else None
    def create_cas(self) -> None:
        bits = int(self.bits.currentText())

        def job(report):
            report("Đang sinh khoá Root CA…")
            root = CertificateAuthority.create("Root CA ATBMTT", bits)
            root.self_signed_root()
            report("Đang sinh khoá Intermediate CA…")
            inter = root.create_intermediate("Intermediate CA ATBMTT", bits)
            report("Đang sinh khoá TSA…")
            tsa = TimestampAuthority.create("TSA ATBMTT", bits)
            tsa.certificate = root.issue(tsa.name, tsa.public_key)
            return root, inter, tsa

        def done(res) -> None:
            self.root, self.inter, self.tsa = res
            self.people.clear()
            self.bundle = None
            self.refresh()
            self.out.clear()
            self.out.append("=== Root CA tự ký chứng chỉ gốc ===\n")
            self.out.append(self.root.certificate.describe() + "\n")
            self.out.append("\n=== Root CA cấp chứng chỉ CA trung gian (is_ca = True) ===\n")
            self.out.append(self.inter.certificate.describe() + "\n")
            self.badge.set_info("Đã tạo Root CA, Intermediate CA và TSA")

        self.app.run(job, done, status="Đang tạo CA…", owner=self)

    def issue(self, name: str) -> None:
        if not self._need_cas():
            return
        bits = int(self.bits.currentText())
        inter = self.inter
        display_name = participant_text(name)

        def job():
            keys = generate_keypair(bits)
            return keys, inter.issue({"trang": "Sender", "thuy": "Receiver"}.get(name, name), keys[0])

        def done(res) -> None:
            self.people[name] = res
            self.refresh()
            self.out.append(f"\n=== Intermediate CA cấp chứng chỉ cho {display_name} ===\n")
            self.out.append(res[1].describe() + "\n")
            self.badge.set_info(f"Đã cấp chứng chỉ cho {display_name}")

        self.app.run(job, done, status=f"Đang sinh khoá và cấp chứng chỉ cho {display_name}…", owner=self)

    def show_selected(self) -> None:
        cert = self._selected()
        if cert is None:
            return
        ok, reason = self._status(cert)
        self.out.append(f"\n=== Chứng chỉ của {cert.subject} ===\n")
        self.out.append(cert.describe() + "\n")
        self.out.append(("[HỢP LỆ] " if ok else "[KHÔNG HỢP LỆ] ") + reason + "\n")

    def verify_selected(self) -> None:
        cert = self._selected()
        if cert is None:
            common.show_info(self, "Chọn chứng chỉ", "Chọn một chứng chỉ trong cây trước.")
            return
        ok, reason = self._status(cert)
        self.badge.set_result(ok, reason)

    def revoke_selected(self) -> None:
        cert = self._selected()
        if cert is None or self.root is None:
            common.show_info(self, "Chọn chứng chỉ", "Chọn chứng chỉ cần thu hồi trong cây.")
            return
        if cert.is_self_signed:
            common.show_warning(self, "Không thu hồi được", "Root CA không thể tự thu hồi trong mô phỏng này.")
            return
        issuer = self.root if cert.issuer == self.root.name else self.inter
        issuer.revoke(cert.serial)
        self.refresh()
        self.out.append(f"\n{issuer.name} thu hồi chứng chỉ của {cert.subject} (serial {cert.serial}) và công bố CRL.\n",
                        "bad")
        self.badge.set_info(f"Đã thu hồi chứng chỉ của {cert.subject}")

    def trang_signs(self) -> None:
        if not self._need_cas():
            return
        if "trang" not in self.people:
            common.show_info(self, "Chưa có chứng chỉ", "Bấm '1.2. Cấp chứng chỉ cho Sender' trước.")
            return
        (_, priv), cert = self.people["trang"]
        tsa, contract = self.tsa, self.contract

        def job():
            sig = sign(contract, priv)
            token = tsa.stamp(sig)
            return SignatureBundle("pkcs1v15", "contract.txt", "", sig.hex(), cert.to_dict(), token.to_dict())

        def done(bundle) -> None:
            self.bundle = bundle
            self.out.append("\n=== Sender ký contract.txt, TSA đóng dấu thời gian ===\n")
            self.out.append(f"S     = {bundle.signature_hex[:64]}…\n"
                            f"token = Sign_TSA(SHA256(S) || t), t = {fmt_time(bundle.timestamp_token['time'])}\n")
            self.badge.set_info("Sender đã ký — bấm '2.2. Sender chối bỏ → Third Party phân xử'")

        self.app.run(job, done, status="Sender đang ký…", owner=self)

    def _arbitrate(self, message: bytes) -> None:
        if self.bundle is None:
            common.show_info(self, "Chưa có chữ ký", "Bấm '2.1. Sender ký hợp đồng + dấu thời gian' trước.")
            return
        res = arbitrate(message, self.bundle, [self.root.certificate], self._crls(), self.tsa.public_key,
                        intermediates=[self.inter.certificate])
        self.badge.set_result(res.valid, res.reason)
        self.out.append(("[HỢP LỆ] " if res.valid else "[KHÔNG HỢP LỆ] ") + res.reason + "\n", "ok" if res.valid else "bad")

    def verify_signed(self) -> None:
        if self._need_cas():
            self.out.append("\n--- Sender chối bỏ chữ ký. Third Party kiểm tra: chữ ký, dấu thời gian, chuỗi chứng chỉ tại thời điểm ký ---\n")
            self._arbitrate(self.contract)

    def tamper_contract(self) -> None:
        if self._need_cas():
            self.out.append("\n--- Attacker sửa 1 byte hợp đồng rồi trình chữ ký cũ ---\n")
            bad = bytearray(self.contract)
            bad[len(bad) // 2] ^= 0x01
            self._arbitrate(bytes(bad))
