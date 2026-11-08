"""Colours and the application style sheet."""

from __future__ import annotations

ACCENT = "#0f5c63"
ACCENT_HOVER = "#0a464c"
ACCENT_SOFT = "#e2f0f1"
BG = "#f4f5f7"
CARD = "#ffffff"
BORDER = "#d9dee4"
TEXT = "#1d2329"
MUTED = "#5b6570"
DANGER = "#b42318"
OK = "#1e7a46"
WARN = "#b7791f"

# severity -> (text colour, background, label)
SEVERITY = {
    "critical": ("#ffffff", "#7a1616", "Critical"),
    "high": ("#ffffff", "#c0392b", "High"),
    "warning": ("#4a3000", "#f2c14e", "Medium"),
    "low": ("#ffffff", "#2f6fa8", "Low"),
    "info": ("#ffffff", "#66707b", "Info"),
}
STATUS = {"ok": (OK, "OK"), "warning": (WARN, "Warning"), "error": (DANGER, "Problem"), "unknown": ("#7b8591", "Not checked")}
BANNER = {"info": ("#e7eef6", "#b9cde2", "#1f3f5f"), "warning": ("#fff6e5", "#e9b44c", "#6b4200"),
          "error": ("#fdeceb", "#e8a29b", "#7a1a12"), "ok": ("#e7f6ec", "#a5d6b5", "#14532d")}
VERDICT = {"Loop likely": DANGER, "STP unstable": WARN, "Storm without clear loop": WARN, "Inconclusive": "#66707b",
           "Healthy": OK, "Action needed": DANGER, "Review": WARN, "No exposure seen": OK, "Not assessed": "#66707b"}


def stylesheet() -> str:
    return f"""
QMainWindow, QStackedWidget, QScrollArea, QWidget#Page, QWidget#ScrollBody {{ background: {BG}; }}
QWidget {{ color: {TEXT}; font-size: 10pt; }}
QDialog {{ background: {BG}; }}
QWidget#Header {{ background: {ACCENT}; }}
QLabel#AppTitle {{ font-size: 15pt; font-weight: 600; color: white; }}
QLabel#HeaderNote {{ color: #cfe5e7; }}
QLabel#PageTitle {{ font-size: 18pt; font-weight: 600; }}
QLabel#Muted {{ color: {MUTED}; }}
QLabel#Section {{ font-size: 11pt; font-weight: 600; }}
QLabel#BigNumber {{ font-size: 40pt; font-weight: 600; }}
QLabel#Stat {{ font-size: 16pt; font-weight: 600; }}
QFrame#Card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 10px; }}
QFrame#Footer {{ background: {CARD}; border-top: 1px solid {BORDER}; }}
QPushButton {{ background: {CARD}; border: 1px solid #c3cad2; border-radius: 6px; padding: 7px 16px; }}
QPushButton:hover {{ background: #eef1f4; }}
QPushButton:disabled {{ color: #9aa3ad; background: #eef0f2; }}
QPushButton#Primary {{ background: {ACCENT}; border-color: {ACCENT}; color: white; font-weight: 600; }}
QPushButton#Primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#Primary:disabled {{ background: #a9c4c7; border-color: #a9c4c7; color: white; }}
QPushButton#Danger {{ background: {DANGER}; border-color: {DANGER}; color: white; font-weight: 600; padding: 12px 34px; font-size: 13pt; }}
QPushButton#Choice {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 10px; padding: 18px 22px; text-align: left; font-size: 12pt; }}
QPushButton#Choice:hover {{ border-color: {ACCENT}; background: {ACCENT_SOFT}; }}
QLineEdit, QComboBox, QPlainTextEdit, QTextBrowser, QTableWidget {{ background: white; border: 1px solid #c3cad2; border-radius: 5px; padding: 5px; }}
QTableWidget {{ padding: 0; gridline-color: transparent; }}
QHeaderView::section {{ background: #f0f2f5; border: none; border-bottom: 1px solid {BORDER}; padding: 5px; font-weight: 600; }}
QTableWidget::item:selected {{ background: {ACCENT_SOFT}; color: {TEXT}; }}
QProgressBar {{ background: #e3e7ec; border: none; border-radius: 4px; height: 8px; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}
"""
