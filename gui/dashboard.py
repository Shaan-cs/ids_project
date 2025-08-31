# ids_project/gui/dashboard.py
import sys
import threading
import time
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTabWidget, QTableWidget, QTableWidgetItem,
                             QPushButton, QLabel, QTextEdit, QComboBox, QSpinBox,
                             QGroupBox, QFormLayout, QLineEdit, QCheckBox, QSplitter,
                             QHeaderView, QMessageBox, QFileDialog, QProgressBar)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QIcon
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from database.db_manager import DatabaseManager

class RealTimeGraph(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(self.fig)
        self.setParent(parent)
        
        self.axes = self.fig.add_subplot(111)
        self.axes.set_ylabel('Packets per Second')
        self.axes.set_title('Real-time Network Traffic')
        self.axes.grid(True, alpha=0.3)
        
        self.x_data = []
        self.y_data = []
        self.line, = self.axes.plot([], [], 'b-')
        
        self.axes.set_xlim(0, 60)
        self.axes.set_ylim(0, 100)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_graph)
        self.timer.start(1000)  # Update every second
    
    def update_graph(self, pps=0):
        current_time = time.time()
        
        # Keep only last 60 seconds of data
        self.x_data.append(current_time)
        self.y_data.append(pps)
        
        if len(self.x_data) > 60:
            self.x_data = self.x_data[-60:]
            self.y_data = self.y_data[-60:]
        
        # Convert timestamps to relative seconds
        if self.x_data:
            base_time = self.x_data[0]
            x_relative = [t - base_time for t in self.x_data]
            
            self.line.set_data(x_relative, self.y_data)
            self.axes.set_xlim(0, max(60, max(x_relative) if x_relative else 60))
            
            if self.y_data:
                max_y = max(self.y_data) * 1.1
                self.axes.set_ylim(0, max(100, max_y))
            
            self.draw()

class AlertTable(QTableWidget):
    def __init__(self):
        super().__init__()
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels(['Timestamp', 'Type', 'Source IP', 'Severity', 'Message', 'Action'])
        self.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
    
    def add_alert(self, alert):
        row_position = self.rowCount()
        self.insertRow(row_position)
        
        # Color coding based on severity
        severity_colors = {
            'LOW': QColor(220, 240, 255),
            'MEDIUM': QColor(255, 245, 220),
            'HIGH': QColor(255, 220, 220),
            'CRITICAL': QColor(255, 200, 200)
        }
        
        items = [
            QTableWidgetItem(alert.get('timestamp', '')),
            QTableWidgetItem(alert.get('type', '')),
            QTableWidgetItem(alert.get('source_ip', '')),
            QTableWidgetItem(alert.get('severity', 'MEDIUM')),
            QTableWidgetItem(alert.get('message', '')),
            QTableWidgetItem(alert.get('action_taken', 'Logged'))
        ]
        
        # Set background color based on severity
        severity = alert.get('severity', 'MEDIUM')
        color = severity_colors.get(severity, QColor(255, 245, 220))
        for item in items:
            item.setBackground(color)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        
        for col, item in enumerate(items):
            self.setItem(row_position, col, item)
        
        # Auto-scroll to bottom
        self.scrollToBottom()

class IDSDashboard(QMainWindow):
    update_signal = pyqtSignal(dict)
    
    def __init__(self, ids_core):
        super().__init__()
        self.ids_core = ids_core
        self.db_manager = DatabaseManager()
        self.setup_ui()
        self.setup_signals()
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(2000)  # Update every 2 seconds
    
    def setup_ui(self):
        self.setWindowTitle("IDS/IPS Dashboard")
        self.setGeometry(100, 100, 1200, 800)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Status bar
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Initializing...")
        self.packet_count_label = QLabel("Packets: 0")
        self.alert_count_label = QLabel("Alerts: 0")
        self.blocked_ips_label = QLabel("Blocked IPs: 0")
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.packet_count_label)
        status_layout.addWidget(self.alert_count_label)
        status_layout.addWidget(self.blocked_ips_label)
        status_layout.addStretch()
        
        # Control buttons
        self.start_btn = QPushButton("Start IDS")
        self.stop_btn = QPushButton("Stop IDS")
        self.stop_btn.setEnabled(False)
        
        status_layout.addWidget(self.start_btn)
        status_layout.addWidget(self.stop_btn)
        
        main_layout.addLayout(status_layout)
        
        # Tab widget for different sections
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Dashboard tab
        self.setup_dashboard_tab()
        
        # Alerts tab
        self.setup_alerts_tab()
        
        # Blocked IPs tab
        self.setup_blocked_ips_tab()
        
        # Settings tab
        self.setup_settings_tab()
        
        # Stats tab
        self.setup_stats_tab()
    
    def setup_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)
        
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side: Real-time graph
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.addWidget(QLabel("Real-time Traffic Monitoring"))
        
        self.graph = RealTimeGraph()
        left_layout.addWidget(self.graph)
        
        # Right side: Recent alerts and quick stats
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        
        # Quick stats
        stats_group = QGroupBox("Quick Statistics")
        stats_layout = QFormLayout(stats_group)
        
        self.uptime_label = QLabel("00:00:00")
        self.pps_label = QLabel("0")
        self.tcp_label = QLabel("0")
        self.udp_label = QLabel("0")
        self.icmp_label = QLabel("0")
        
        stats_layout.addRow("Uptime:", self.uptime_label)
        stats_layout.addRow("Packets/sec:", self.pps_label)
        stats_layout.addRow("TCP Packets:", self.tcp_label)
        stats_layout.addRow("UDP Packets:", self.udp_label)
        stats_layout.addRow("ICMP Packets:", self.icmp_label)
        
        right_layout.addWidget(stats_group)
        
        # Recent alerts
        recent_alerts_group = QGroupBox("Recent Alerts (Last 10)")
        recent_layout = QVBoxLayout(recent_alerts_group)
        
        self.recent_alerts_table = AlertTable()
        self.recent_alerts_table.setColumnCount(4)
        self.recent_alerts_table.setHorizontalHeaderLabels(['Time', 'Type', 'IP', 'Severity'])
        recent_layout.addWidget(self.recent_alerts_table)
        
        right_layout.addWidget(recent_alerts_group)
        
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setSizes([700, 300])
        
        layout.addWidget(splitter)
        self.tabs.addTab(dashboard_tab, "Dashboard")
    
    def setup_alerts_tab(self):
        alerts_tab = QWidget()
        layout = QVBoxLayout(alerts_tab)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by:"))
        
        self.alert_type_filter = QComboBox()
        self.alert_type_filter.addItems(["All", "PORT_SCAN", "SYN_FLOOD", "BRUTE_FORCE", "DOS_ATTACK"])
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        
        self.time_filter = QComboBox()
        self.time_filter.addItems(["Last hour", "Last 24 hours", "Last 7 days", "All time"])
        
        filter_layout.addWidget(QLabel("Type:"))
        filter_layout.addWidget(self.alert_type_filter)
        filter_layout.addWidget(QLabel("Severity:"))
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addWidget(QLabel("Time:"))
        filter_layout.addWidget(self.time_filter)
        
        self.filter_btn = QPushButton("Apply Filter")
        self.export_btn = QPushButton("Export to CSV")
        self.clear_btn = QPushButton("Clear Alerts")
        
        filter_layout.addWidget(self.filter_btn)
        filter_layout.addWidget(self.export_btn)
        filter_layout.addWidget(self.clear_btn)
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Alerts table
        self.alerts_table = AlertTable()
        layout.addWidget(self.alerts_table)
        
        self.tabs.addTab(alerts_tab, "Alerts")
    
    def setup_blocked_ips_tab(self):
        blocked_tab = QWidget()
        layout = QVBoxLayout(blocked_tab)
        
        # Controls
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("Manual IP Management:"))
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address")
        
        self.block_reason = QLineEdit()
        self.block_reason.setPlaceholderText("Reason for blocking")
        
        self.block_btn = QPushButton("Block IP")
        self.unblock_btn = QPushButton("Unblock Selected")
        self.whitelist_btn = QPushButton("Add to Whitelist")
        
        control_layout.addWidget(self.ip_input)
        control_layout.addWidget(self.block_reason)
        control_layout.addWidget(self.block_btn)
        control_layout.addWidget(self.unblock_btn)
        control_layout.addWidget(self.whitelist_btn)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
        # Blocked IPs table
        self.blocked_ips_table = QTableWidget()
        self.blocked_ips_table.setColumnCount(5)
        self.blocked_ips_table.setHorizontalHeaderLabels(['IP Address', 'Block Time', 'Unblock Time', 'Reason', 'Time Left'])
        self.blocked_ips_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.blocked_ips_table)
        
        self.tabs.addTab(blocked_tab, "Blocked IPs")
    
    def setup_settings_tab(self):
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # Detection thresholds
        thresholds_group = QGroupBox("Detection Thresholds")
        thresholds_layout = QFormLayout(thresholds_group)
        
        self.port_scan_threshold = QSpinBox()
        self.port_scan_threshold.setRange(5, 100)
        self.port_scan_threshold.setValue(20)
        
        self.syn_flood_threshold = QSpinBox()
        self.syn_flood_threshold.setRange(10, 1000)
        self.syn_flood_threshold.setValue(100)
        
        self.brute_force_threshold = QSpinBox()
        self.brute_force_threshold.setRange(3, 50)
        self.brute_force_threshold.setValue(10)
        
        self.dos_threshold = QSpinBox()
        self.dos_threshold.setRange(100, 10000)
        self.dos_threshold.setValue(1000)
        
        self.block_duration = QSpinBox()
        self.block_duration.setRange(60, 3600)
        self.block_duration.setValue(600)
        self.block_duration.setSuffix(" seconds")
        
        thresholds_layout.addRow("Port Scan (ports/min):", self.port_scan_threshold)
        thresholds_layout.addRow("SYN Flood (SYN/sec):", self.syn_flood_threshold)
        thresholds_layout.addRow("Brute Force (attempts/min):", self.brute_force_threshold)
        thresholds_layout.addRow("DoS (packets/sec):", self.dos_threshold)
        thresholds_layout.addRow("Block Duration:", self.block_duration)
        
        layout.addWidget(thresholds_group)
        
        # Notification settings
        notif_group = QGroupBox("Notifications")
        notif_layout = QVBoxLayout(notif_group)
        
        self.email_notif = QCheckBox("Enable Email Notifications")
        self.telegram_notif = QCheckBox("Enable Telegram Notifications")
        
        email_form = QFormLayout()
        self.email_server = QLineEdit()
        self.email_port = QSpinBox()
        self.email_port.setRange(1, 65535)
        self.email_port.setValue(587)
        self.email_user = QLineEdit()
        self.email_password = QLineEdit()
        self.email_password.setEchoMode(QLineEdit.Password)
        self.email_recipient = QLineEdit()
        
        email_form.addRow("SMTP Server:", self.email_server)
        email_form.addRow("SMTP Port:", self.email_port)
        email_form.addRow("Username:", self.email_user)
        email_form.addRow("Password:", self.email_password)
        email_form.addRow("Recipient:", self.email_recipient)
        
        telegram_form = QFormLayout()
        self.telegram_bot_token = QLineEdit()
        self.telegram_chat_id = QLineEdit()
        
        telegram_form.addRow("Bot Token:", self.telegram_bot_token)
        telegram_form.addRow("Chat ID:", self.telegram_chat_id)
        
        notif_layout.addWidget(self.email_notif)
        notif_layout.addLayout(email_form)
        notif_layout.addWidget(self.telegram_notif)
        notif_layout.addLayout(telegram_form)
        
        layout.addWidget(notif_group)
        
        # Save button
        self.save_btn = QPushButton("Save Settings")
        layout.addWidget(self.save_btn)
        
        layout.addStretch()
        self.tabs.addTab(settings_tab, "Settings")
    
    def setup_stats_tab(self):
        stats_tab = QWidget()
        layout = QVBoxLayout(stats_tab)
        
        # Time range selector
        time_layout = QHBoxLayout()
        time_layout.addWidget(QLabel("Statistics Time Range:"))
        
        self.stats_time_range = QComboBox()
        self.stats_time_range.addItems(["Last hour", "Last 24 hours", "Last 7 days", "Last 30 days"])
        
        self.generate_stats_btn = QPushButton("Generate Report")
        self.export_stats_btn = QPushButton("Export Statistics")
        
        time_layout.addWidget(self.stats_time_range)
        time_layout.addWidget(self.generate_stats_btn)
        time_layout.addWidget(self.export_stats_btn)
        time_layout.addStretch()
        
        layout.addLayout(time_layout)
        
        # Stats display area
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        layout.addWidget(self.stats_text)
        
        self.tabs.addTab(stats_tab, "Statistics")
    
    def setup_signals(self):
        # Connect buttons
        self.start_btn.clicked.connect(self.start_ids)
        self.stop_btn.clicked.connect(self.stop_ids)
        self.filter_btn.clicked.connect(self.apply_alert_filter)
        self.export_btn.clicked.connect(self.export_alerts)
        self.clear_btn.clicked.connect(self.clear_alerts)
        self.block_btn.clicked.connect(self.manual_block_ip)
        self.unblock_btn.clicked.connect(self.manual_unblock_ip)
        self.whitelist_btn.clicked.connect(self.add_to_whitelist)
        self.save_btn.clicked.connect(self.save_settings)
        self.generate_stats_btn.clicked.connect(self.generate_stats)
        self.export_stats_btn.clicked.connect(self.export_statistics)
        
        # Connect update signal
        self.update_signal.connect(self.handle_real_time_update)
    
    def start_ids(self):
        if self.ids_core.start():
            self.status_label.setText("Running")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status_label.setStyleSheet("color: green; font-weight: bold;")
    
    def stop_ids(self):
        self.ids_core.stop()
        self.status_label.setText("Stopped")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
    
    def update_dashboard(self):
        # Update status information
        status = self.ids_core.status()
        stats = self.ids_core.sniffer.get_stats()
        
        # Update labels
        self.packet_count_label.setText(f"Packets: {stats.get('total_packets', 0)}")
        self.alert_count_label.setText(f"Alerts: {len(self.db_manager.get_recent_alerts(limit=1000))}")
        self.blocked_ips_label.setText(f"Blocked IPs: {len(status.get('blocked_ips', {}))}")
        
        # Update traffic stats
        self.pps_label.setText(f"{stats.get('packets_per_second', 0):.1f}")
        self.tcp_label.setText(str(stats.get('tcp_packets', 0)))
        self.udp_label.setText(str(stats.get('udp_packets', 0)))
        self.icmp_label.setText(str(stats.get('icmp_packets', 0)))
        
        # Update uptime
        uptime_seconds = status.get('uptime_seconds', 0)
        hours, remainder = divmod(uptime_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.uptime_label.setText(f"{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
        
        # Update graph
        self.graph.update_graph(stats.get('packets_per_second', 0))
        
        # Update recent alerts
        self.update_recent_alerts()
        
        # Update blocked IPs table
        self.update_blocked_ips_table()
    
    def update_recent_alerts(self):
        alerts = self.db_manager.get_recent_alerts(limit=10)
        self.recent_alerts_table.setRowCount(0)
        
        for alert in alerts:
            row_position = self.recent_alerts_table.rowCount()
            self.recent_alerts_table.insertRow(row_position)
            
            items = [
                QTableWidgetItem(alert.get('timestamp', '')[:19]),  # Shorten timestamp
                QTableWidgetItem(alert.get('type', '')),
                QTableWidgetItem(alert.get('source_ip', '')),
                QTableWidgetItem(alert.get('severity', 'MEDIUM'))
            ]
            
            for col, item in enumerate(items):
                self.recent_alerts_table.setItem(row_position, col, item)
    
    def update_blocked_ips_table(self):
        blocked_ips = self.ids_core.firewall.get_blocked_ips()
        self.blocked_ips_table.setRowCount(0)
        
        for ip, info in blocked_ips.items():
            row_position = self.blocked_ips_table.rowCount()
            self.blocked_ips_table.insertRow(row_position)
            
            time_left = info.get('time_remaining', 0)
            minutes, seconds = divmod(time_left, 60)
            time_left_str = f"{int(minutes)}m {int(seconds)}s" if time_left > 0 else "Expired"
            
            items = [
                QTableWidgetItem(ip),
                QTableWidgetItem(info.get('block_time', '')[:19]),
                QTableWidgetItem(info.get('unblock_time', '')[:19]),
                QTableWidgetItem(info.get('reason', '')),
                QTableWidgetItem(time_left_str)
            ]
            
            for col, item in enumerate(items):
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.blocked_ips_table.setItem(row_position, col, item)
    
    def apply_alert_filter(self):
        alert_type = self.alert_type_filter.currentText()
        severity = self.severity_filter.currentText()
        time_range = self.time_filter.currentText()
        
        # Convert time range to datetime
        now = datetime.now()
        if time_range == "Last hour":
            start_time = now.replace(hour=now.hour - 1)
        elif time_range == "Last 24 hours":
            start_time = now.replace(day=now.day - 1)
        elif time_range == "Last 7 days":
            start_time = now.replace(day=now.day - 7)
        else:  # All time
            start_time = None
        
        # Get filtered alerts
        alerts = self.db_manager.get_filtered_alerts(
            alert_type if alert_type != "All" else None,
            severity if severity != "All" else None,
            start_time
        )
        
        # Update alerts table
        self.alerts_table.setRowCount(0)
        for alert in alerts:
            self.alerts_table.add_alert(alert)
    
    def export_alerts(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Alerts", "", "CSV Files (*.csv);;JSON Files (*.json)"
        )
        
        if file_path:
            if file_path.endswith('.csv'):
                success = self.db_manager.export_alerts_to_csv(file_path)
            else:
                success = self.db_manager.export_alerts_to_json(file_path)
            
            if success:
                QMessageBox.information(self, "Export Successful", "Alerts exported successfully!")
            else:
                QMessageBox.warning(self, "Export Failed", "Failed to export alerts.")
    
    def clear_alerts(self):
        reply = QMessageBox.question(
            self, "Confirm Clear", 
            "Are you sure you want to clear all alerts? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.db_manager.clear_alerts()
            self.alerts_table.setRowCount(0)
            QMessageBox.information(self, "Cleared", "All alerts have been cleared.")
    
    def manual_block_ip(self):
        ip = self.ip_input.text().strip()
        reason = self.block_reason.text().strip()
        
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address.")
            return
        
        # Simple IP validation
        if not self.is_valid_ip(ip):
            QMessageBox.warning(self, "Input Error", "Please enter a valid IP address.")
            return
        
        if self.ids_core.firewall.block_ip(ip, reason or "Manually blocked by administrator"):
            QMessageBox.information(self, "Success", f"IP {ip} has been blocked.")
            self.ip_input.clear()
            self.block_reason.clear()
            self.update_blocked_ips_table()
        else:
            QMessageBox.warning(self, "Error", f"Failed to block IP {ip}.")
    
    def manual_unblock_ip(self):
        selected_rows = self.blocked_ips_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Selection Error", "Please select an IP to unblock.")
            return
        
        for index in selected_rows:
            ip = self.blocked_ips_table.item(index.row(), 0).text()
            if self.ids_core.firewall.unblock_ip(ip):
                QMessageBox.information(self, "Success", f"IP {ip} has been unblocked.")
            else:
                QMessageBox.warning(self, "Error", f"Failed to unblock IP {ip}.")
        
        self.update_blocked_ips_table()
    
    def add_to_whitelist(self):
        ip = self.ip_input.text().strip()
        if not ip:
            QMessageBox.warning(self, "Input Error", "Please enter an IP address.")
            return
        
        if not self.is_valid_ip(ip):
            QMessageBox.warning(self, "Input Error", "Please enter a valid IP address.")
            return
        
        self.ids_core.detector.add_to_whitelist(ip)
        QMessageBox.information(self, "Success", f"IP {ip} has been added to whitelist.")
        self.ip_input.clear()
    
    def save_settings(self):
        # Update detection thresholds
        self.ids_core.detector.thresholds['port_scan']['max_ports_per_minute'] = self.port_scan_threshold.value()
        self.ids_core.detector.thresholds['syn_flood']['max_syn_per_second'] = self.syn_flood_threshold.value()
        self.ids_core.detector.thresholds['brute_force']['max_attempts_per_minute'] = self.brute_force_threshold.value()
        self.ids_core.detector.thresholds['dos_attack']['max_packets_per_second'] = self.dos_threshold.value()
        
        # Update block duration
        self.ids_core.firewall.set_block_duration(self.block_duration.value())
        
        # TODO: Save notification settings to config file
        
        QMessageBox.information(self, "Settings Saved", "All settings have been saved successfully.")
    
    def generate_stats(self):
        time_range = self.stats_time_range.currentText()
        now = datetime.now()
        
        if time_range == "Last hour":
            start_time = now.replace(hour=now.hour - 1)
        elif time_range == "Last 24 hours":
            start_time = now.replace(day=now.day - 1)
        elif time_range == "Last 7 days":
            start_time = now.replace(day=now.day - 7)
        else:  # Last 30 days
            start_time = now.replace(day=now.day - 30)
        
        stats = self.db_manager.get_statistics(start_time)
        
        # Format statistics for display
        stats_text = f"Statistics for {time_range}\n"
        stats_text += "=" * 50 + "\n\n"
        
        stats_text += f"Total Alerts: {stats.get('total_alerts', 0)}\n"
        stats_text += f"Blocked IPs: {stats.get('blocked_ips', 0)}\n\n"
        
        stats_text += "Alert Types:\n"
        for alert_type, count in stats.get('alert_types', {}).items():
            stats_text += f"  {alert_type}: {count}\n"
        
        stats_text += "\nSeverity Distribution:\n"
        for severity, count in stats.get('severity_dist', {}).items():
            stats_text += f"  {severity}: {count}\n"
        
        stats_text += "\nTop Source IPs:\n"
        for ip, count in stats.get('top_source_ips', {}).items():
            stats_text += f"  {ip}: {count} alerts\n"
        
        self.stats_text.setPlainText(stats_text)
    
    def export_statistics(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Statistics", "", "Text Files (*.txt);;CSV Files (*.csv)"
        )
        
        if file_path:
            stats_text = self.stats_text.toPlainText()
            try:
                with open(file_path, 'w') as f:
                    f.write(stats_text)
                QMessageBox.information(self, "Export Successful", "Statistics exported successfully!")
            except Exception as e:
                QMessageBox.warning(self, "Export Failed", f"Failed to export statistics: {e}")
    
    def handle_real_time_update(self, data):
        # Handle real-time updates from the IDS core
        if data.get('type') == 'alert':
            self.alerts_table.add_alert(data)
            self.update_recent_alerts()
    
    def is_valid_ip(self, ip):
        # Simple IP validation
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            if not part.isdigit():
                return False
            if not 0 <= int(part) <= 255:
                return False
        
        return True
    
    def closeEvent(self, event):
        # Stop IDS when closing the application
        self.ids_core.stop()
        event.accept()

def run_gui(ids_core):
    app = QApplication(sys.argv)
    dashboard = IDSDashboard(ids_core)
    dashboard.show()
    sys.exit(app.exec_())