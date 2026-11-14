"""Smoke test GUI (pytest-qt): mở cửa sổ, Tiny với h = 88 hiển thị s = 11, tab Kiểm thử toàn ✅."""
import pytest

pytest.importorskip("PySide6")
pytest.importorskip("pytestqt")

from demo.gui.main_window import MainWindow, create_app  # noqa: E402
from demo.gui.widgets import common  # noqa: E402


@pytest.fixture
def window(qtbot, monkeypatch):
    create_app(["test"])
    for name in ("show_info", "show_warning", "show_error"):
        monkeypatch.setattr(common, name, lambda *a, **k: None)
    w = MainWindow()
    qtbot.addWidget(w)
    w.show()
    return w


def _wait(qtbot, w, timeout=120_000):
    qtbot.waitUntil(lambda: not w.busy, timeout=timeout)


def test_window_has_seven_tabs(window):
    assert window.tabs.count() == 7
    assert window.minimumWidth() >= 1100 and window.minimumHeight() >= 750


def test_tiny_x88_shows_y11(window):
    tab = window.tiny_tab
    tab.load_class_example()
    tab.sign()
    assert tab.y.value() == 11
    assert any("y = 11" in t for t in tab.steps.card_texts())
    assert tab.euclid.rowCount() > 0 and tab.sm_sign.rowCount() == 5
    tab.verify()
    assert "HỢP LỆ" in tab.badge.text() and "KHÔNG" not in tab.badge.text()


def test_tiny_sign_then_encrypt(window):
    tab = window.tiny_tab
    tab.load_class_example()
    tab.encrypt_flow.setChecked(True)
    tab.sign()
    tab.encrypt()
    assert tab._z == [264, 189]
    tab.decrypt_verify()
    assert tab.badge.text() == "HỢP LỆ"
    tab.tamper_z()
    tab.decrypt_verify()
    assert tab.badge.text() == "KHÔNG HỢP LỆ"


def test_tiny_shows_all_steps(window):
    tab = window.tiny_tab
    tab.load_class_example()
    assert tab.steps.shown > 0 and not tab.steps.has_next()
    tab.sign()
    assert tab.steps.shown > 0 and not tab.steps.has_next()
    assert any("y = 11" in text for text in tab.steps.card_texts())
    tab.verify()
    assert tab.steps.shown > 0 and not tab.steps.has_next()


def test_explanations_number_mixed_steps_and_keep_data(window):
    from PySide6.QtWidgets import QLabel

    from core.step_logger import StepLogger
    from demo.gui.widgets.common import OutputBox

    log = StepLogger()
    log.head("KỊCH BẢN S1")
    log.note("[1] trang ký", "M = trang_sign.json")
    log.ok("    thuy kiểm tra")
    log.head("[2] Third Party phân xử")
    log.note("[3] phuong thử giả mạo")
    log.note("Bình phương và nhân")
    view = window.attacks_tab.steps
    view.set_steps(log.steps, reveal_all=False)
    while view.has_next():
        view.next_step()
    titles = [view._lay.itemAt(i).widget().findChild(QLabel).text() for i in range(len(log.steps))]
    assert titles == [
        "KỊCH BẢN S1", "1. Sender ký", "2. Receiver kiểm tra",
        "3. Third Party phân xử", "4. Attacker thử giả mạo",
        "5. Bình phương và nhân",
    ]
    assert "M = trang_sign.json" in view.card_texts()
    output = OutputBox()
    output.append_steps(log)
    assert all(title in output.text() for title in titles)
    view.set_steps(log.steps)
    assert view._lay.itemAt(1).widget().findChild(QLabel).text() == titles[1]


def test_formulas_and_step_values_are_literal_text(window):
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel

    from core.step_logger import StepLogger
    from demo.gui.widgets.formula_label import FormulaLabel

    formula = "t < t_r; s₃ = (s₁ · s₂) mod n"
    body = "Thông điệp gốc: <b>hợp đồng</b> & dữ liệu"
    log = StepLogger()
    log.log("Công thức và dữ liệu", formula, body)
    view = window.attacks_tab.steps
    view.set_steps(log.steps)
    label = view.findChild(FormulaLabel)
    assert label.text() == label.toolTip() == formula
    assert label.textFormat() == Qt.TextFormat.PlainText
    value = next(label for label in view.findChildren(QLabel) if label.text() == body)
    assert value.textFormat() == Qt.TextFormat.PlainText
    assert formula in log.to_text() and body in log.to_text()


def test_sign_verify_text_and_tamper(window, qtbot):
    tab = window.sign_tab
    window.tabs.setCurrentWidget(tab)
    if tab.priv is None:
        tab.bits.setCurrentText("1024")
        tab.generate()
        _wait(qtbot, window)
    tab.src.set_text("Hợp đồng 2.000.000.000 VNĐ")
    tab.sign()
    _wait(qtbot, window)
    tab.verify()
    _wait(qtbot, window)
    assert tab.badge.text() == "HỢP LỆ"
    tab.flip_message()
    tab.verify()
    _wait(qtbot, window)
    assert tab.badge.text() == "KHÔNG HỢP LỆ"


def test_attack_tab_runs(window, qtbot):
    tab = window.attacks_tab
    window.tabs.setCurrentWidget(tab)
    tab.select("a1_no_hash_forgery")
    tab.run_selected()
    _wait(qtbot, window)
    assert "THÀNH CÔNG" in tab.badge.text()
    texts = tab.steps.card_texts()
    assert "s₃ = (s₁ · s₂) mod n" in texts
    assert not any("\\" in text for text in texts)
    tab.defended.setChecked(True)
    tab.run_selected()
    _wait(qtbot, window)
    assert "THẤT BẠI" in tab.badge.text()


def test_test_tab_all_green(window, qtbot):
    tab = window.test_tab
    window.tabs.setCurrentWidget(tab)
    tab.start()
    _wait(qtbot, window, 300_000)
    assert tab.rows and all(r.match for r in tab.rows)
    assert tab.table.rowCount() == len(tab.rows)
