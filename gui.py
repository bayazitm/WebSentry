import json
import math
import os
import sys
import threading
import traceback
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QThread, QTimer, Qt, Signal, QPointF, QUrl, QStandardPaths
from PySide6.QtGui import QColor, QDesktopServices, QFont, QFontDatabase, QIcon, QPainter
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QPushButton, QSplitter, QTabWidget,
    QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget,
    QAbstractItemView,
)

from engine import VERSION, LIMITATIONS, ScanCancelled, ScanError, scan
from reports import COLORS, detail_html, esc, save_report

STYLE = """
QWidget {background:#10131b;color:#e8edf5;font-family:'Segoe UI';font-size:13px;}
QLabel {background:transparent;} QLabel#brand {font-size:24px;font-weight:700;}
QLabel#muted {color:#9ca9bd;font-size:12px;} QLabel#metric {font-size:29px;font-weight:700;}
QFrame#card {background:#191f2c;border:1px solid #2b3445;border-radius:10px;}
QLineEdit {background:#191f2c;border:1px solid #354055;border-radius:8px;padding:12px 14px;selection-background-color:#62548d;}
QLineEdit:focus {border-color:#b6a5fa;}
QPushButton {background:#242d3d;border:1px solid #39465c;border-radius:7px;padding:10px 15px;font-weight:600;}
QPushButton:hover {background:#323f55;} QPushButton:disabled {color:#727f94;background:#1b2230;border-color:#2d3747;}
QPushButton#primary {background:#b6a5fa;color:#18132a;border-color:#b6a5fa;}
QPushButton#primary:hover {background:#c8baff;} QPushButton#primary:disabled {background:#403b56;color:#9e94b6;border-color:#403b56;}
QComboBox {background:#191f2c;border:1px solid #354055;border-radius:6px;padding:8px 12px;min-width:135px;}
QComboBox QAbstractItemView {background:#20283a;selection-background-color:#51456d;}
QTabWidget::pane {border:1px solid #2b3445;border-radius:7px;}
QTabBar::tab {padding:10px 17px;color:#a0acc0;background:#10131b;border-bottom:2px solid transparent;}
QTabBar::tab:selected {color:#e8edf5;border-bottom:2px solid #b6a5fa;}
QTableWidget {background:#151b26;alternate-background-color:#181f2c;border:none;gridline-color:#253044;selection-background-color:#33334b;selection-color:#fff;}
QTableWidget::item {padding:8px;border-bottom:1px solid #242f41;}
QHeaderView::section {background:#1b2331;color:#a6b3c9;padding:10px;border:none;border-bottom:1px solid #354055;}
QTextBrowser {background:#151b26;color:#e8edf5;border:none;padding:16px;selection-background-color:#51456d;}
QSplitter::handle {background:#293245;width:2px;}
QScrollBar:vertical {background:#151b26;width:8px;} QScrollBar::handle:vertical {background:#465169;border-radius:4px;min-height:30px;}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical {height:0;}
"""


class Spinner(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(24, 24)
        self.phase = 0
        self.timer = QTimer(self)
        self.timer.setInterval(70)
        self.timer.timeout.connect(self.advance)
        self.hide()
        self.setAccessibleName("Analysis in progress")

    def advance(self):
        self.phase = (self.phase + 1) % 12
        self.update()

    def set_busy(self, busy):
        self.setVisible(busy)
        self.timer.start() if busy else self.timer.stop()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        for i in range(12):
            angle = math.radians((i + self.phase) * 30)
            color = QColor("#b6a5fa")
            color.setAlpha(35 + 20 * i)
            painter.setBrush(color)
            painter.drawEllipse(QPointF(12 + 8 * math.cos(angle), 12 + 8 * math.sin(angle)), 1.8, 1.8)
        painter.end()


class ScanJob(QThread):
    report_ready = Signal(dict)
    failed = Signal(str, bool)
    stage = Signal(str)

    def __init__(self, url, parent=None):
        super().__init__(parent)
        self.url = url
        self.cancelled = threading.Event()

    def run(self):
        try:
            report = scan(self.url, self.cancelled, self.stage.emit)
            if not self.cancelled.is_set():
                self.report_ready.emit(report)
            else:
                self.failed.emit("Scan cancelled.", True)
        except ScanCancelled as exc:
            self.failed.emit(str(exc), True)
        except ScanError as exc:
            self.failed.emit(str(exc), False)
        except Exception:
            self.failed.emit("The scan could not complete. No security assessment was produced.", False)


def label(text, name=None):
    widget = QLabel(text)
    widget.setWordWrap(True)
    if name:
        widget.setObjectName(name)
    return widget


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WebSentry · HTTP Security Header Analyzer")
        self.resize(1160, 800)
        self.setMinimumSize(920, 660)
        self.report = None
        self.job = None
        self.close_pending = False
        self.visible_findings = []
        self.last_export = None
        root = QWidget()
        self.setCentralWidget(root)
        page = QVBoxLayout(root)
        page.setContentsMargins(26, 20, 26, 18)
        page.setSpacing(14)
        heading = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QIcon(str(asset_root() / "assets/websentry.svg")).pixmap(36, 36))
        heading.addWidget(icon)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        titles.addWidget(label("WebSentry", "brand"))
        titles.addWidget(label("HTTP security header analysis", "muted"))
        heading.addLayout(titles)
        heading.addStretch()
        self.html_button = self.button("Export HTML", lambda: self.export("html"))
        self.json_button = self.button("Export JSON", lambda: self.export("json"))
        for button in (self.html_button, self.json_button):
            button.setEnabled(False)
            heading.addWidget(button)
        page.addLayout(heading)
        query = QHBoxLayout()
        self.url = QLineEdit()
        self.url.setPlaceholderText("Enter a website URL, e.g. https://example.com")
        self.url.setAccessibleName("Website URL")
        self.url.setMaxLength(4096)
        self.url.returnPressed.connect(self.start_scan)
        query.addWidget(self.url, 1)
        self.analyze = self.button("Analyze", self.start_scan, True)
        query.addWidget(self.analyze)
        self.cancel = self.button("Cancel", self.cancel_scan)
        self.cancel.hide()
        query.addWidget(self.cancel)
        page.addLayout(query)
        activity = QHBoxLayout()
        self.spinner = Spinner()
        activity.addWidget(self.spinner)
        self.status = label("Ready. Enter a URL to inspect its response headers.", "muted")
        self.status.setMinimumHeight(32)
        activity.addWidget(self.status, 1)
        page.addLayout(activity)
        metrics = QHBoxLayout()
        self.metrics = {}
        for name, color in COLORS.items():
            card = QFrame()
            card.setObjectName("card")
            layout = QVBoxLayout(card)
            layout.setContentsMargins(16, 10, 16, 10)
            number = label("—", "metric")
            number.setStyleSheet("color:" + color)
            self.metrics[name] = number
            layout.addWidget(number)
            layout.addWidget(label(name, "muted"))
            metrics.addWidget(card, 1)
        page.addLayout(metrics)
        self.context = label("One response at a time. Evidence and recommended actions are shown for every check.", "muted")
        self.context.setTextFormat(Qt.TextFormat.PlainText)
        self.context.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        page.addWidget(self.context)
        self.tabs = QTabWidget()
        findings_page = QWidget()
        findings_layout = QVBoxLayout(findings_page)
        findings_layout.setContentsMargins(0, 12, 0, 0)
        tools = QHBoxLayout()
        tools.addWidget(label("FINDINGS", "muted"))
        tools.addStretch()
        self.filter = QComboBox()
        self.filter.addItems(["All findings", *COLORS.keys()])
        self.filter.setAccessibleName("Filter findings by status")
        self.filter.currentTextChanged.connect(self.populate_findings)
        tools.addWidget(self.filter)
        findings_layout.addLayout(tools)
        split = QSplitter()
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Status", "Control", "Observation"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setDefaultSectionSize(48)
        self.table.itemSelectionChanged.connect(self.show_finding)
        split.addWidget(self.table)
        self.details = QTextBrowser()
        self.details.setOpenExternalLinks(True)
        self.details.setHtml("<h2>Understand the response.</h2><p>Analyze a URL, then select a finding to see the observed value, explanation and suggested action.</p><p>Counts summarize checks, not the overall security of a website.</p>")
        split.addWidget(self.details)
        split.setSizes([630, 410])
        findings_layout.addWidget(split, 1)
        self.tabs.addTab(findings_page, "Findings")
        self.headers = QTableWidget(0, 2)
        self.headers.setHorizontalHeaderLabels(["Response header", "Observed value"])
        self.headers.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.headers.verticalHeader().hide()
        self.headers.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.headers.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.headers.setWordWrap(True)
        self.tabs.addTab(self.headers, "Response headers")
        self.chain = QTextBrowser()
        self.chain.setHtml("<h2>Request chain</h2><p>Redirects will appear here after a scan.</p>")
        self.tabs.addTab(self.chain, "Redirects & scope")
        about = QTextBrowser()
        about.setOpenExternalLinks(True)
        about.setHtml("<h2>WebSentry " + VERSION + "</h2><p>A local HTTP response header inspector.</p><h3>What the results mean</h3><p><b>Pass</b>: the specific check found its expected condition.<br><b>Warning</b>: a missing or risky condition was observed.<br><b>Review</b>: interpretation depends on syntax or deployment context.<br><b>Info</b>: context or optional hardening information.<br><b>Not applicable</b>: the check does not apply to this response.</p><h3>Scope</h3><ul>" + "".join("<li>" + esc(note) + "</li>" for note in LIMITATIONS) + "</ul><p>Only explicit exports write reports. No scan history or browser sessions are imported. Queries and sensitive headers are redacted in reports. System proxies are not imported.</p><p><a href='https://secure-headers-project.owasp.org/response-headers/'>OWASP Secure Headers</a> · <a href='https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers'>MDN HTTP Headers</a></p>")
        self.tabs.addTab(about, "About")
        page.addWidget(self.tabs, 1)
        footer = QHBoxLayout()
        footer.addWidget(label("Response headers only · No exploit tests · No overall security score", "muted"), 1)
        self.open_report = self.button("Open last report", self.open_last_report)
        self.open_report.setEnabled(False)
        footer.addWidget(self.open_report)
        page.addLayout(footer)

    def button(self, text, callback, primary=False):
        button = QPushButton(text)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        if primary:
            button.setObjectName("primary")
        button.clicked.connect(callback)
        return button

    def set_status(self, message, error=False):
        self.status.setText(message)
        self.status.setStyleSheet("color:#ffb589" if error else "color:#a6b3ca")

    def start_scan(self):
        if self.job:
            return
        from engine import normalize_url
        try:
            target = normalize_url(self.url.text())
        except ScanError as exc:
            self.set_status(str(exc), True)
            return
        self.report = None
        self.table.setRowCount(0)
        self.headers.setRowCount(0)
        self.visible_findings = []
        self.details.setHtml("<h2>Analyzing response headers…</h2><p>The interface remains available. Cancellation takes effect after any in-flight network operation returns.</p>")
        self.chain.clear()
        self.context.setText("Waiting for the final HTTP response…")
        for number in self.metrics.values():
            number.setText("—")
        self.filter.setCurrentIndex(0)
        self.set_busy(True)
        self.set_status("Connecting…")
        self.job = ScanJob(target, self)
        self.job.report_ready.connect(self.display_report)
        self.job.failed.connect(self.scan_failed)
        self.job.stage.connect(lambda message: self.set_status(message + "…") if self.job and not self.job.cancelled.is_set() else None)
        self.job.finished.connect(self.scan_finished)
        self.job.start()

    def set_busy(self, busy):
        self.spinner.set_busy(busy)
        self.analyze.setEnabled(not busy)
        self.url.setEnabled(not busy)
        self.cancel.setVisible(busy)
        self.cancel.setEnabled(busy)
        self.html_button.setEnabled(not busy and self.report is not None)
        self.json_button.setEnabled(not busy and self.report is not None)

    def cancel_scan(self):
        if self.job:
            self.job.cancelled.set()
            self.cancel.setEnabled(False)
            self.set_status("Cancelling… waiting for the current connection to return.")

    def scan_failed(self, message, cancelled):
        self.report = None
        self.set_status(message, not cancelled)
        self.details.setHtml("<h2>" + ("Scan cancelled" if cancelled else "Could not complete analysis") + "</h2><p>" + esc(message) + "</p><p>No assessment was produced for this request.</p>")
        self.context.setText("No result for this request.")

    def scan_finished(self):
        job = self.job
        self.job = None
        if job:
            job.deleteLater()
        self.set_busy(False)
        if self.close_pending:
            QTimer.singleShot(0, self.close)

    def display_report(self, report):
        self.report = report
        for status, number in self.metrics.items():
            number.setText(str(report["summary"][status]))
        self.context.setText(f"{report['final_url']}\nHTTP {report['http_status']} · {report['content_type']} · {report['elapsed_ms']} ms · {report['scanned_at']}")
        self.populate_findings()
        self.headers.setRowCount(len(report["response_headers"]))
        for row, pair in enumerate(report["response_headers"]):
            for column, value in enumerate(pair):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.headers.setItem(row, column, item)
        self.headers.resizeRowsToContents()
        hops = "".join(f"<li><b>HTTP {hop['status']}</b> · {esc(hop['url'])}</li>" for hop in report["redirect_chain"])
        scope = "".join("<li>" + esc(note) + "</li>" for note in report["limitations"])
        self.chain.setHtml("<h2>Request chain</h2><ol>" + hops + "</ol><h2>Scope &amp; limitations</h2><ul>" + scope + "</ul>")
        self.tabs.setCurrentIndex(0)
        self.set_status("Analysis complete. Select a finding for evidence and suggested actions." if report["http_status"] < 400 else f"HTTP {report['http_status']}: results describe this error/challenge response; see Scope.")
        if not self.job:
            self.set_busy(False)

    def populate_findings(self, *_):
        if not self.report:
            return
        selected = self.filter.currentText()
        self.visible_findings = [item for item in self.report["findings"] if selected == "All findings" or item["status"] == selected]
        self.table.setRowCount(len(self.visible_findings))
        for row, finding in enumerate(self.visible_findings):
            for column, text in enumerate((finding["status"], finding["header"], finding["title"])):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                if column == 0:
                    item.setForeground(QColor(COLORS[finding["status"]]))
                self.table.setItem(row, column, item)
        if self.visible_findings:
            self.table.selectRow(0)
            self.show_finding()
        else:
            self.details.setHtml("<h2>No matching findings</h2><p>Choose another status filter.</p>")

    def show_finding(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.visible_findings):
            self.details.setHtml(detail_html(self.visible_findings[row]))

    def export(self, kind):
        if not self.report:
            return
        base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation) or str(Path.home())
        host = urlsplit(self.report["final_url"]).hostname or "report"
        host = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)
        filename = str(Path(base) / f"WebSentry-{host}.{kind}")
        destination, _ = QFileDialog.getSaveFileName(self, "Export report", filename, f"{kind.upper()} report (*.{kind})")
        if not destination:
            return
        if not destination.lower().endswith("." + kind):
            destination += "." + kind
        try:
            save_report(self.report, destination, kind)
        except (OSError, ValueError):
            self.set_status("Could not save the report. Check the destination and available space.", True)
            return
        self.last_export = destination
        self.open_report.setEnabled(True)
        self.set_status("Report saved: " + destination)

    def open_last_report(self):
        if self.last_export:
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.last_export))

    def closeEvent(self, event):
        if self.job and self.job.isRunning():
            self.close_pending = True
            self.cancel_scan()
            event.ignore()
        else:
            event.accept()


def asset_root():
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def application():
    app = QApplication.instance() or QApplication(sys.argv)
    if sys.platform == "win32" and os.environ.get("QT_QPA_PLATFORM") == "offscreen":
        font = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "segoeui.ttf"
        if font.is_file():
            QFontDatabase.addApplicationFont(str(font))
    app.setApplicationName("WebSentry")
    app.setOrganizationName("WebSentry")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    app.setWindowIcon(QIcon(str(asset_root() / "assets/websentry.svg")))
    return app


def run():
    app = application()
    window = MainWindow()
    screen = app.primaryScreen()
    if screen:
        available = screen.availableGeometry()
        window.resize(min(1160, available.width() - 50), min(800, available.height() - 60))
    window.show()
    return app.exec()


def self_test(destination):
    try:
        from engine import build_report
        app = application()
        window = MainWindow()
        report = build_report("https://example.test/", "https://example.test/", 200,
                              [("Content-Type", "text/html"), ("X-Content-Type-Options", "nosniff")],
                              [{"url": "https://example.test/", "status": 200}], 1)
        window.display_report(report)
        window.show()
        app.processEvents()
        assert window.table.rowCount() == len(report["findings"])
        assert window.html_button.isEnabled()
        screenshot = str(Path(destination).with_suffix(".png"))
        window.grab().save(screenshot)
        Path(destination).write_text(json.dumps({"ok": True, "checks": window.table.rowCount(), "screenshot": screenshot}), encoding="utf-8")
        window.close()
        return 0
    except Exception:
        Path(destination).write_text(json.dumps({"ok": False, "error": traceback.format_exc()}), encoding="utf-8")
        return 1
