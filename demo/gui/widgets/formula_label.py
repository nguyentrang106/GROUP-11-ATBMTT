from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QLabel

from demo.gui.widgets.common import PLUM, UI_FONT, UI_PX


class FormulaLabel(QLabel):
    def __init__(self, formula: str | None = None) -> None:
        super().__init__()
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setWordWrap(True)
        font = QFont(UI_FONT)
        font.setPixelSize(UI_PX + 1)
        self.setFont(font)
        self.setStyleSheet(f"color: {PLUM}; background: transparent;")
        self.set_formula(formula)

    def set_formula(self, formula: str | None) -> None:
        text = formula or ""
        self.setText(text)
        self.setToolTip(text)
