import sys
import threading

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QComboBox,
    QSpinBox, QRadioButton, QCheckBox, QButtonGroup,
    QFileDialog, QTextEdit, QProgressBar, QGroupBox,
    QMessageBox, QSizePolicy,
)
from PyQt6.QtGui import QFont

from crypto import (
    SUITE_PARAMS, DEFAULT_SUITE, DEFAULT_ITER,
    encrypt, decrypt, HMACVerificationError,
)

SUITE_IDS    = list(SUITE_PARAMS.keys())
SUITE_LABELS = [SUITE_PARAMS[sid]["label"] for sid in SUITE_IDS]


def _suite_id(label: str) -> int:
    for sid, p in SUITE_PARAMS.items():
        if p["label"] == label:
            return sid
    return DEFAULT_SUITE


# ---------------------------------------------------------------------------
# Worker threads
# ---------------------------------------------------------------------------

class _EncryptWorker(QObject):
    finished = pyqtSignal(str)   # empty string = success, else error message

    def __init__(self, plaintext, password, suite_id, iterations, include_meta, use_hkdf, out_path):
        super().__init__()
        self._plaintext   = plaintext
        self._password    = password
        self._suite_id    = suite_id
        self._iterations  = iterations
        self._include_meta = include_meta
        self._use_hkdf    = use_hkdf
        self._out_path    = out_path

    def run(self):
        try:
            blob = encrypt(
                self._plaintext, self._password,
                suite_id=self._suite_id, iterations=self._iterations,
                include_metadata_in_hmac=self._include_meta, use_hkdf=self._use_hkdf,
            )
            with open(self._out_path, "wb") as f:
                f.write(blob)
            self.finished.emit("")
        except Exception as e:
            self.finished.emit(str(e))


class _DecryptWorker(QObject):
    finished = pyqtSignal(object, str)  # (plaintext_bytes_or_None, error_str)

    def __init__(self, data, password):
        super().__init__()
        self._data     = data
        self._password = password

    def run(self):
        try:
            plaintext = decrypt(self._data, self._password)
            self.finished.emit(plaintext, "")
        except HMACVerificationError as e:
            self.finished.emit(None, f"Authentication failed: {e}")
        except Exception as e:
            self.finished.emit(None, str(e))


# ---------------------------------------------------------------------------
# Encrypt tab
# ---------------------------------------------------------------------------

class EncryptTab(QWidget):
    def __init__(self, settings: dict):
        super().__init__()
        self._settings = settings
        self._thread   = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # --- Input mode ---
        mode_group = QGroupBox("Input source")
        mode_layout = QHBoxLayout(mode_group)
        self._rb_file = QRadioButton("File")
        self._rb_text = QRadioButton("Text")
        self._rb_file.setChecked(True)
        self._rb_file.toggled.connect(self._toggle_input)
        mode_layout.addWidget(self._rb_file)
        mode_layout.addWidget(self._rb_text)
        mode_layout.addStretch()
        layout.addWidget(mode_group)

        # --- Input file ---
        self._input_file_row = QWidget()
        ifl = QHBoxLayout(self._input_file_row)
        ifl.setContentsMargins(0, 0, 0, 0)
        ifl.addWidget(QLabel("Input file:"))
        self._input_path = QLineEdit()
        ifl.addWidget(self._input_path, 1)
        btn_ib = QPushButton("Browse…")
        btn_ib.clicked.connect(self._browse_input)
        ifl.addWidget(btn_ib)
        layout.addWidget(self._input_file_row)

        # --- Input text ---
        self._input_text_row = QWidget()
        itl = QVBoxLayout(self._input_text_row)
        itl.setContentsMargins(0, 0, 0, 0)
        itl.addWidget(QLabel("Input text:"))
        self._input_text = QTextEdit()
        self._input_text.setFixedHeight(80)
        itl.addWidget(self._input_text)
        self._input_text_row.hide()
        layout.addWidget(self._input_text_row)

        # --- Output file ---
        out_row = QWidget()
        orl = QHBoxLayout(out_row)
        orl.setContentsMargins(0, 0, 0, 0)
        orl.addWidget(QLabel("Output file:"))
        self._output_path = QLineEdit()
        orl.addWidget(self._output_path, 1)
        btn_ob = QPushButton("Browse…")
        btn_ob.clicked.connect(self._browse_output)
        orl.addWidget(btn_ob)
        layout.addWidget(out_row)

        # --- Suite ---
        suite_row = QWidget()
        srl = QHBoxLayout(suite_row)
        srl.setContentsMargins(0, 0, 0, 0)
        srl.addWidget(QLabel("Suite:"))
        self._suite_cb = QComboBox()
        self._suite_cb.addItems(SUITE_LABELS)
        self._suite_cb.setCurrentText(SUITE_PARAMS[self._settings["suite"]]["label"])
        self._suite_cb.currentTextChanged.connect(self._on_suite_change)
        srl.addWidget(self._suite_cb, 1)
        layout.addWidget(suite_row)

        # Legacy warning
        self._legacy_lbl = QLabel("⚠  3DES is deprecated (SWEET32). Use AES for new data.")
        self._legacy_lbl.setStyleSheet("color: darkorange; font-weight: bold;")
        self._legacy_lbl.hide()
        layout.addWidget(self._legacy_lbl)

        # --- Iterations ---
        iter_row = QWidget()
        itrl = QHBoxLayout(iter_row)
        itrl.setContentsMargins(0, 0, 0, 0)
        itrl.addWidget(QLabel("Iterations:"))
        self._iter_spin = QSpinBox()
        self._iter_spin.setRange(10_000, 10_000_000)
        self._iter_spin.setSingleStep(10_000)
        default_hash = SUITE_PARAMS[self._settings["suite"]]["hash"]
        self._iter_spin.setValue(self._settings[f"iter_{default_hash.lower().replace('-', '')}"])
        itrl.addWidget(self._iter_spin)
        itrl.addStretch()
        layout.addWidget(iter_row)

        # --- Password ---
        pw_row = QWidget()
        pwl = QHBoxLayout(pw_row)
        pwl.setContentsMargins(0, 0, 0, 0)
        pwl.addWidget(QLabel("Password:"))
        self._pw = QLineEdit()
        self._pw.setEchoMode(QLineEdit.EchoMode.Password)
        pwl.addWidget(self._pw, 1)
        pwl.addWidget(QLabel("Confirm:"))
        self._pw2 = QLineEdit()
        self._pw2.setEchoMode(QLineEdit.EchoMode.Password)
        pwl.addWidget(self._pw2, 1)
        layout.addWidget(pw_row)

        # --- Encrypt button + progress ---
        btn_row = QWidget()
        btrl = QHBoxLayout(btn_row)
        btrl.setContentsMargins(0, 0, 0, 0)
        self._enc_btn = QPushButton("Encrypt")
        self._enc_btn.setFixedWidth(100)
        self._enc_btn.clicked.connect(self._do_encrypt)
        btrl.addWidget(self._enc_btn)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)   # indeterminate
        self._progress.hide()
        btrl.addWidget(self._progress, 1)
        layout.addWidget(btn_row)

        # --- Status ---
        self._status = QLabel("")
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        layout.addStretch()

    def _toggle_input(self):
        if self._rb_file.isChecked():
            self._input_text_row.hide()
            self._input_file_row.show()
        else:
            self._input_file_row.hide()
            self._input_text_row.show()

    def _browse_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select input file")
        if path:
            self._input_path.setText(path)

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save encrypted file", filter="Encrypted (*.enc);;All files (*)")
        if path:
            self._output_path.setText(path)

    def _on_suite_change(self, label: str):
        sid = _suite_id(label)
        p = SUITE_PARAMS[sid]
        self._legacy_lbl.setVisible(p["legacy"])
        key = f"iter_{p['hash'].lower().replace('-', '')}"
        self._iter_spin.setValue(self._settings[key])

    def _set_busy(self, busy: bool):
        self._enc_btn.setEnabled(not busy)
        self._progress.setVisible(busy)

    def _do_encrypt(self):
        pw  = self._pw.text()
        pw2 = self._pw2.text()
        if pw != pw2:
            QMessageBox.critical(self, "Error", "Passwords do not match.")
            return
        if not pw:
            QMessageBox.critical(self, "Error", "Password cannot be empty.")
            return

        out_path = self._output_path.text().strip()
        if not out_path:
            QMessageBox.critical(self, "Error", "Please specify an output file.")
            return

        if self._rb_file.isChecked():
            in_path = self._input_path.text().strip()
            if not in_path:
                QMessageBox.critical(self, "Error", "Please specify an input file.")
                return
            if in_path == out_path:
                QMessageBox.critical(self, "Error", "Input and output paths must differ.")
                return
            try:
                with open(in_path, "rb") as f:
                    plaintext = f.read()
            except OSError as e:
                QMessageBox.critical(self, "Error", f"Cannot read input file:\n{e}")
                return
        else:
            plaintext = self._input_text.toPlainText().encode("utf-8")

        sid        = _suite_id(self._suite_cb.currentText())
        iterations = self._iter_spin.value()
        use_hkdf   = self._settings["use_hkdf"]
        inc_meta   = self._settings["include_meta_hmac"]

        self._set_busy(True)
        self._status.setText("Encrypting…")

        worker = _EncryptWorker(
            plaintext, pw.encode("utf-8"), sid, iterations, inc_meta, use_hkdf, out_path
        )
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(lambda err: self._enc_done(err, out_path, thread))
        worker.finished.connect(thread.quit)
        thread.start()
        self._thread = thread

    def _enc_done(self, error: str, out_path: str, thread: QThread):
        thread.wait()
        self._set_busy(False)
        self._pw.clear()
        self._pw2.clear()
        if error:
            self._status.setStyleSheet("color: red;")
            self._status.setText(f"Error: {error}")
        else:
            self._status.setStyleSheet("color: green;")
            self._status.setText(f"Encrypted successfully → {out_path}")


# ---------------------------------------------------------------------------
# Decrypt tab
# ---------------------------------------------------------------------------

class DecryptTab(QWidget):
    def __init__(self, settings: dict):
        super().__init__()
        self._settings = settings
        self._thread   = None
        self._build()

    def _build(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # --- Input file ---
        in_row = QWidget()
        irl = QHBoxLayout(in_row)
        irl.setContentsMargins(0, 0, 0, 0)
        irl.addWidget(QLabel("Input file:"))
        self._input_path = QLineEdit()
        irl.addWidget(self._input_path, 1)
        btn_ib = QPushButton("Browse…")
        btn_ib.clicked.connect(self._browse_input)
        irl.addWidget(btn_ib)
        layout.addWidget(in_row)

        # --- Output mode ---
        mode_group = QGroupBox("Output destination")
        mgl = QHBoxLayout(mode_group)
        self._rb_file    = QRadioButton("File")
        self._rb_display = QRadioButton("Display in app")
        self._rb_file.setChecked(True)
        self._rb_file.toggled.connect(self._toggle_output)
        mgl.addWidget(self._rb_file)
        mgl.addWidget(self._rb_display)
        mgl.addStretch()
        layout.addWidget(mode_group)

        # --- Output file ---
        self._out_file_row = QWidget()
        ofl = QHBoxLayout(self._out_file_row)
        ofl.setContentsMargins(0, 0, 0, 0)
        ofl.addWidget(QLabel("Output file:"))
        self._output_path = QLineEdit()
        ofl.addWidget(self._output_path, 1)
        btn_ob = QPushButton("Browse…")
        btn_ob.clicked.connect(self._browse_output)
        ofl.addWidget(btn_ob)
        layout.addWidget(self._out_file_row)

        # --- Display area ---
        self._out_display_row = QWidget()
        odl = QVBoxLayout(self._out_display_row)
        odl.setContentsMargins(0, 0, 0, 0)
        odl.addWidget(QLabel("Decrypted output:"))
        self._out_text = QTextEdit()
        self._out_text.setReadOnly(True)
        self._out_text.setFixedHeight(100)
        odl.addWidget(self._out_text)
        self._out_display_row.hide()
        layout.addWidget(self._out_display_row)

        # --- Password ---
        pw_row = QWidget()
        pwl = QHBoxLayout(pw_row)
        pwl.setContentsMargins(0, 0, 0, 0)
        pwl.addWidget(QLabel("Password:"))
        self._pw = QLineEdit()
        self._pw.setEchoMode(QLineEdit.EchoMode.Password)
        pwl.addWidget(self._pw, 1)
        layout.addWidget(pw_row)

        # --- Decrypt button + progress ---
        btn_row = QWidget()
        btrl = QHBoxLayout(btn_row)
        btrl.setContentsMargins(0, 0, 0, 0)
        self._dec_btn = QPushButton("Decrypt")
        self._dec_btn.setFixedWidth(100)
        self._dec_btn.clicked.connect(self._do_decrypt)
        btrl.addWidget(self._dec_btn)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.hide()
        btrl.addWidget(self._progress, 1)
        layout.addWidget(btn_row)

        # --- Status ---
        self._status = QLabel("")
        self._status.setWordWrap(True)
        layout.addWidget(self._status)
        layout.addStretch()

    def _toggle_output(self):
        if self._rb_file.isChecked():
            self._out_display_row.hide()
            self._out_file_row.show()
        else:
            self._out_file_row.hide()
            self._out_display_row.show()

    def _browse_input(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select encrypted file")
        if path:
            self._input_path.setText(path)

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save decrypted file")
        if path:
            self._output_path.setText(path)

    def _set_busy(self, busy: bool):
        self._dec_btn.setEnabled(not busy)
        self._progress.setVisible(busy)

    def _do_decrypt(self):
        in_path = self._input_path.text().strip()
        pw      = self._pw.text()

        if not in_path:
            QMessageBox.critical(self, "Error", "Please specify an input file.")
            return
        if not pw:
            QMessageBox.critical(self, "Error", "Password cannot be empty.")
            return
        if self._rb_file.isChecked() and not self._output_path.text().strip():
            QMessageBox.critical(self, "Error", "Please specify an output file.")
            return

        try:
            with open(in_path, "rb") as f:
                data = f.read()
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Cannot read file:\n{e}")
            return

        self._set_busy(True)
        self._status.setText("Decrypting…")

        out_path = self._output_path.text().strip() if self._rb_file.isChecked() else None

        worker = _DecryptWorker(data, pw.encode("utf-8"))
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(lambda pt, err: self._dec_done(pt, err, out_path, thread))
        worker.finished.connect(thread.quit)
        thread.start()
        self._thread = thread

    def _dec_done(self, plaintext: bytes | None, error: str, out_path: str | None, thread: QThread):
        thread.wait()
        self._set_busy(False)
        self._pw.clear()

        if error:
            self._status.setStyleSheet("color: red;")
            self._status.setText(f"Error: {error}")
            return

        if out_path:
            try:
                with open(out_path, "wb") as f:
                    f.write(plaintext)
                self._status.setStyleSheet("color: green;")
                self._status.setText(f"Decrypted successfully → {out_path}")
            except OSError as e:
                self._status.setStyleSheet("color: red;")
                self._status.setText(f"Write error: {e}")
        else:
            try:
                text = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                text = f"[Binary data ({len(plaintext)} bytes) — save to file to view]"
            self._out_text.setPlainText(text)
            self._status.setStyleSheet("color: green;")
            self._status.setText("Decrypted successfully.")


# ---------------------------------------------------------------------------
# Settings tab
# ---------------------------------------------------------------------------

class SettingsTab(QWidget):
    def __init__(self, settings: dict):
        super().__init__()
        self._settings = settings
        self._build()

    def _build(self):
        layout = QGridLayout(self)
        layout.setSpacing(10)
        layout.setColumnMinimumWidth(1, 300)

        layout.addWidget(QLabel("Default suite:"), 0, 0)
        self._suite_cb = QComboBox()
        self._suite_cb.addItems(SUITE_LABELS)
        self._suite_cb.setCurrentText(SUITE_PARAMS[self._settings["suite"]]["label"])
        layout.addWidget(self._suite_cb, 0, 1)

        layout.addWidget(QLabel("SHA-256 iterations:"), 1, 0)
        self._iter256 = QSpinBox()
        self._iter256.setRange(10_000, 10_000_000)
        self._iter256.setSingleStep(10_000)
        self._iter256.setValue(self._settings["iter_sha256"])
        layout.addWidget(self._iter256, 1, 1)

        layout.addWidget(QLabel("SHA-512 iterations:"), 2, 0)
        self._iter512 = QSpinBox()
        self._iter512.setRange(10_000, 10_000_000)
        self._iter512.setSingleStep(10_000)
        self._iter512.setValue(self._settings["iter_sha512"])
        layout.addWidget(self._iter512, 2, 1)

        layout.addWidget(QLabel("2nd-stage derivation:"), 3, 0)
        kdf_widget = QWidget()
        kdfl = QHBoxLayout(kdf_widget)
        kdfl.setContentsMargins(0, 0, 0, 0)
        self._rb_pbkdf2 = QRadioButton("PBKDF2 (default)")
        self._rb_hkdf   = QRadioButton("HKDF")
        if self._settings["use_hkdf"]:
            self._rb_hkdf.setChecked(True)
        else:
            self._rb_pbkdf2.setChecked(True)
        kdfl.addWidget(self._rb_pbkdf2)
        kdfl.addWidget(self._rb_hkdf)
        kdfl.addStretch()
        layout.addWidget(kdf_widget, 3, 1)

        layout.addWidget(QLabel("Metadata in HMAC:"), 4, 0)
        self._meta_cb = QCheckBox("Include (recommended)")
        self._meta_cb.setChecked(self._settings["include_meta_hmac"])
        layout.addWidget(self._meta_cb, 4, 1)

        apply_btn = QPushButton("Apply Settings")
        apply_btn.setFixedWidth(140)
        apply_btn.clicked.connect(self._apply)
        layout.addWidget(apply_btn, 5, 0, 1, 2)

        self._status = QLabel("")
        layout.addWidget(self._status, 6, 0, 1, 2)
        layout.setRowStretch(7, 1)

    def _apply(self):
        self._settings["suite"]             = _suite_id(self._suite_cb.currentText())
        self._settings["iter_sha256"]       = self._iter256.value()
        self._settings["iter_sha512"]       = self._iter512.value()
        self._settings["use_hkdf"]          = self._rb_hkdf.isChecked()
        self._settings["include_meta_hmac"] = self._meta_cb.isChecked()
        self._status.setStyleSheet("color: green;")
        self._status.setText("Settings applied.")


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption Utility")
        self.setMinimumSize(620, 500)

        self._settings = {
            "suite":            DEFAULT_SUITE,
            "iter_sha256":      DEFAULT_ITER["SHA-256"],
            "iter_sha512":      DEFAULT_ITER["SHA-512"],
            "use_hkdf":         False,
            "include_meta_hmac": True,
        }

        tabs = QTabWidget()
        tabs.addTab(EncryptTab(self._settings), "  Encrypt  ")
        tabs.addTab(DecryptTab(self._settings), "  Decrypt  ")
        tabs.addTab(SettingsTab(self._settings), "  Settings  ")
        self.setCentralWidget(tabs)


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
