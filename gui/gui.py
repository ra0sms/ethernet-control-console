import sys
import serial
import serial.tools.list_ports
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QTextEdit,
    QGroupBox, QFormLayout, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
import re
import time


class SerialReader(QThread):
    data_received = pyqtSignal(str)

    def __init__(self, ser):
        super().__init__()
        self.ser = ser
        self.running = True

    def run(self):
        buffer = ""
        while self.running and self.ser.is_open:
            try:
                if self.ser.in_waiting:
                    chunk = self.ser.read(self.ser.in_waiting).decode('utf-8', errors='ignore')
                    buffer += chunk
                    if '\r\n' in buffer:
                        lines = buffer.split('\r\n')
                        buffer = lines[-1]
                        for line in lines[:-1]:
                            if line.strip():
                                self.data_received.emit(line)
            except Exception as e:
                self.data_received.emit(f"ERROR: {e}")
                break
        if self.ser.is_open:
            self.ser.close()

    def stop(self):
        self.running = False


class LANControlGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.ser = None
        self.reader_thread = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("LAN Control")
        self.resize(520, 560)
        layout = QVBoxLayout()

        # === Port & Connect ===
        top_layout = QHBoxLayout()
        self.port_combo = QComboBox()
        self.refresh_ports()
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.toggle_connection)

        top_layout.addWidget(QLabel("Port:"))
        top_layout.addWidget(self.port_combo, 1)
        top_layout.addWidget(self.connect_btn)

        refresh_ports_btn = QPushButton("Refresh")
        refresh_ports_btn.clicked.connect(self.refresh_ports)
        top_layout.addWidget(refresh_ports_btn)

        layout.addLayout(top_layout)

        # === Network Settings ===
        net_group = QGroupBox("Network")
        net_layout = QFormLayout()
        net_layout.setSpacing(5)
        self.ip_edit = QLineEdit("192.168.0.250")
        self.mac_edit = QLineEdit("00:08:DC:AB:CD:EF")
        self.subnet_edit = QLineEdit("255.255.255.0")
        self.gateway_edit = QLineEdit("192.168.0.1")
        self.dns_edit = QLineEdit("8.8.8.8")

        net_layout.addRow("IP:", self.ip_edit)
        net_layout.addRow("MAC:", self.mac_edit)
        net_layout.addRow("Mask:", self.subnet_edit)
        net_layout.addRow("GW:", self.gateway_edit)
        net_layout.addRow("DNS:", self.dns_edit)
        net_group.setLayout(net_layout)
        layout.addWidget(net_group)

        # === Auth Settings ===
        auth_group = QGroupBox("Authentication")
        auth_layout = QHBoxLayout()
        self.user_edit = QLineEdit("admin")
        self.pass_edit = QLineEdit("password")  # ← открытое поле
        get_auth_btn = QPushButton("Get")
        get_auth_btn.clicked.connect(self.get_auth)

        auth_layout.addWidget(QLabel("Login:"))
        auth_layout.addWidget(self.user_edit)
        auth_layout.addWidget(QLabel("Pass:"))
        auth_layout.addWidget(self.pass_edit)
        auth_layout.addWidget(get_auth_btn)
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)

        # === Button Names ===
        buttons_group = QGroupBox("Buttons (0–7)")
        buttons_layout = QFormLayout()
        buttons_layout.setSpacing(3)
        self.button_edits = []
        row_layouts = [QHBoxLayout() for _ in range(4)]
        for i in range(8):
            edit = QLineEdit(f"OUT{i+1}")
            self.button_edits.append(edit)
            row_idx = i // 2
            row_layouts[row_idx].addWidget(QLabel(f"{i}:"))
            row_layouts[row_idx].addWidget(edit, 1)
        for row in row_layouts:
            buttons_layout.addRow(row)
        buttons_group.setLayout(buttons_layout)
        layout.addWidget(buttons_group)

        # === Apply Buttons (три специализированные) ===
        apply_layout = QHBoxLayout()
        self.apply_net_btn = QPushButton("Apply Network")
        self.apply_net_btn.clicked.connect(self.apply_network)
        self.apply_btn_btn = QPushButton("Apply Buttons")
        self.apply_btn_btn.clicked.connect(self.apply_buttons)
        self.apply_auth_btn = QPushButton("Apply Auth")
        self.apply_auth_btn.clicked.connect(self.apply_auth)

        apply_layout.addWidget(self.apply_net_btn)
        apply_layout.addWidget(self.apply_btn_btn)
        apply_layout.addWidget(self.apply_auth_btn)
        layout.addLayout(apply_layout)

        # === Bottom Buttons ===
        bottom_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh All")
        self.refresh_btn.clicked.connect(self.refresh_all)
        self.save_btn = QPushButton("💾 Save EEPROM")
        self.save_btn.clicked.connect(self.save_to_eeprom)
        self.reset_btn = QPushButton("🔁 Reset Device")
        self.reset_btn.clicked.connect(self.reset_device)

        bottom_layout.addWidget(self.refresh_btn)
        bottom_layout.addWidget(self.save_btn)
        bottom_layout.addWidget(self.reset_btn)
        layout.addLayout(bottom_layout)

        # === Log Output ===
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(100)
        self.log_output.setStyleSheet("font-family: monospace; font-size: 8pt; padding: 4px;")
        layout.addWidget(QLabel("Log:"))
        layout.addWidget(self.log_output)

        self.setLayout(layout)
        self.set_controls_enabled(False)

    def set_controls_enabled(self, enabled):
        for w in [
            self.refresh_btn, self.save_btn, self.reset_btn,
            self.apply_net_btn, self.apply_btn_btn, self.apply_auth_btn
        ]:
            w.setEnabled(enabled)
        for edit in [self.ip_edit, self.mac_edit, self.subnet_edit,
                     self.gateway_edit, self.dns_edit,
                     self.user_edit, self.pass_edit]:
            edit.setEnabled(enabled)
        for edit in self.button_edits:
            edit.setEnabled(enabled)

    def refresh_ports(self):
        self.port_combo.clear()
        ports = serial.tools.list_ports.comports()
        for port in ports:
            self.port_combo.addItem(f"{port.device}")

    def toggle_connection(self):
        if self.ser and self.ser.is_open:
            self.disconnect_serial()
        else:
            self.connect_serial()

    def connect_serial(self):
        port_name = self.port_combo.currentText()
        if not port_name:
            QMessageBox.warning(self, "Port", "No port selected!")
            return
        try:
            self.ser = serial.Serial(port_name, 115200, timeout=0.5)
            time.sleep(1.2)
            self.reader_thread = SerialReader(self.ser)
            self.reader_thread.data_received.connect(self.on_data_received)
            self.reader_thread.start()
            self.connect_btn.setText("Disconnect")
            self.set_controls_enabled(True)
            self.log("✅ Connected")
            self.refresh_all()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open {port_name}:\n{e}")

    def disconnect_serial(self):
        if self.reader_thread:
            self.reader_thread.stop()
            self.reader_thread.wait(2000)
        if self.ser and self.ser.is_open:
            try:
                self.ser.close()
            except:
                pass
        self.connect_btn.setText("Connect")
        self.set_controls_enabled(False)
        self.log("🔌 Disconnected")

    def log(self, msg):
        self.log_output.append(f"> {msg}")

    def send_command(self, cmd, delay=0.15):
        if not self.ser or not self.ser.is_open:
            self.log("❌ Not connected!")
            return
        try:
            self.ser.write(f"{cmd}\r\n".encode())
            self.log(f"📤 {cmd}")
            time.sleep(delay)
        except Exception as e:
            self.log(f"❌ Send failed: {e}")

    def on_data_received(self, line):
        # Парсинг Network
        if "IP:" in line and "Subnet:" not in line:
            match = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                self.ip_edit.setText(match.group(1))
        elif "MAC:" in line:
            match = re.search(r"MAC: ([0-9A-F:]{17})", line, re.IGNORECASE)
            if match:
                self.mac_edit.setText(match.group(1).upper())
        elif "Subnet:" in line:
            match = re.search(r"Subnet: (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                self.subnet_edit.setText(match.group(1))
        elif "Gateway:" in line:
            match = re.search(r"Gateway: (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                self.gateway_edit.setText(match.group(1))
        elif "DNS:" in line:
            match = re.search(r"DNS: (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                self.dns_edit.setText(match.group(1))
        # Парсинг кнопок
        elif "Button" in line and ":" in line and "Button Names" not in line:
            match = re.search(r"Button (\d+):\s*(.+)", line)
            if match:
                idx = int(match.group(1))
                if 0 <= idx < 8:
                    name = match.group(2).strip()
                    if name:
                        self.button_edits[idx].setText(name)
        # Парсинг Auth
        elif line.startswith("HTTP User: "):
            user = line.split("HTTP User: ", 1)[1].strip()
            self.user_edit.setText(user)
        elif line.startswith("HTTP Pass: "):
            pwd = line.split("HTTP Pass: ", 1)[1].strip()
            self.pass_edit.setText(pwd)

        self.log(f"📥 {line}")

    def refresh_all(self):
        self.send_command("network", delay=0.25)
        self.send_command("buttons", delay=0.25)
        self.send_command("get user", delay=0.15)
        self.send_command("get pass", delay=0.15)

    def apply_network(self):
        ip = self.ip_edit.text().strip()
        mac = self.mac_edit.text().strip()
        sn = self.subnet_edit.text().strip()
        gw = self.gateway_edit.text().strip()
        dns = self.dns_edit.text().strip()

        if not all([ip, mac, sn, gw, dns]):
            QMessageBox.warning(self, "Input Error", "All network fields must be filled.")
            return

        self.send_command(f"set ip {ip}")
        self.send_command(f"set mac {mac}")
        self.send_command(f"set subnet {sn}")
        self.send_command(f"set gateway {gw}")
        self.send_command(f"set dns {dns}")
        QMessageBox.information(self, "✅ Applied", "Network settings applied (RAM only).")

    def apply_buttons(self):
        for i in range(8):
            name = self.button_edits[i].text().strip()
            if not name:
                QMessageBox.warning(self, "Input Error", f"Button {i} name cannot be empty.")
                return
            if len(name) > 15:
                QMessageBox.warning(self, "Input Error", f"Button {i} name too long (>15).")
                return
        for i in range(8):
            name = self.button_edits[i].text().strip()
            self.send_command(f"setbutton {i} {name}")
        QMessageBox.information(self, "✅ Applied", "Button names applied (RAM only).")

    def apply_auth(self):
        user = self.user_edit.text().strip()
        pwd = self.pass_edit.text().strip()
        if not user or not pwd:
            QMessageBox.warning(self, "Input Error", "Login and password cannot be empty.")
            return
        if len(user) > 31 or len(pwd) > 31:
            QMessageBox.warning(self, "Input Error", "Max length: 31 chars (login/password).")
            return
        self.send_command(f"set user {user}", delay=0.2)
        self.send_command(f"set pass {pwd}", delay=0.2)
        QMessageBox.information(self, "✅ Applied", "Auth settings updated (RAM only).")

    def get_auth(self):
        self.send_command("get user", delay=0.15)
        self.send_command("get pass", delay=0.15)

    def save_to_eeprom(self):
        reply = QMessageBox.question(
            self, "💾 Confirm Save",
            "Save ALL current settings to EEPROM?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.send_command("save", delay=0.5)
            self.log("💾 Saved to EEPROM")

    def reset_device(self):
        if not self.ser or not self.ser.is_open:
            self.log("❌ Not connected!")
            return

        reply = QMessageBox.question(
            self, "🔁 Confirm Reset",
            "Send 'reset' command? Device will reboot (~2s).",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        self.log("📤 reset")
        try:
            self.ser.write(b"reset\r\n")
        except:
            pass
        time.sleep(0.1)

        if self.reader_thread:
            self.reader_thread.stop()
            self.reader_thread.wait(2000)
        if self.ser:
            try:
                self.ser.close()
            except:
                pass

        self.connect_btn.setText("Connect")
        self.set_controls_enabled(False)
        self.reset_btn.setEnabled(False)
        self.log("⏳ Device is rebooting...")

        QTimer.singleShot(2200, self.auto_reconnect_after_reset)

    def auto_reconnect_after_reset(self):
        self.log("🔌 Auto-reconnecting after reset...")
        self.connect_serial()
        if self.ser and self.ser.is_open:
            QTimer.singleShot(600, self.refresh_all)
        self.reset_btn.setEnabled(True)

    def closeEvent(self, event):
        self.disconnect_serial()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LANControlGUI()
    window.show()
    sys.exit(app.exec_())