# rabbitWEBscan - part of the HACKrabbitMQ Suite
# Copyright (C) 2025 Garland Glessner - gglesner@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from PySide6.QtWidgets import QApplication, QWidget, QPlainTextEdit, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFrame, QGridLayout, QFileDialog, QSpacerItem, QSizePolicy, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
import datetime
import csv
import os
import requests
from requests.auth import HTTPBasicAuth
import json

# Define the version number at the top
VERSION = "1.0.1"

# Define the tab label for the tab widget
TAB_LABEL = f"RabbitWEBscan v{VERSION}"

class Ui_TabContent:
    def setupUi(self, widget):
        """Set up the UI components for the WEBscan tab."""
        widget.setObjectName("TabContent")

        # Main vertical layout with reduced spacing
        self.verticalLayout_3 = QVBoxLayout(widget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout_3.setSpacing(5)

        self.verticalLayout_3.addSpacerItem(QSpacerItem(0, 1, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Header frame with title and input fields
        self.frame_8 = QFrame(widget)
        self.frame_8.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_3 = QHBoxLayout(self.frame_8)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)

        self.frame_5 = QFrame(self.frame_8)
        self.frame_5.setFrameShape(QFrame.StyledPanel)
        self.horizontalLayout_3.addWidget(self.frame_5)

        self.label_3 = QLabel(self.frame_8)
        font = QFont("Courier New", 14)
        font.setBold(True)
        self.label_3.setFont(font)
        self.label_3.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.horizontalLayout_3.addWidget(self.label_3)

        self.frame_10 = QFrame(self.frame_8)
        self.frame_10.setFrameShape(QFrame.NoFrame)
        self.gridLayout_2 = QGridLayout(self.frame_10)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setVerticalSpacing(0)

        # Port input frame
        self.frame_11 = QFrame(self.frame_10)
        self.frame_11.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_5 = QHBoxLayout(self.frame_11)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)

        self.PortLabel = QLabel(self.frame_11)
        self.horizontalLayout_5.addWidget(self.PortLabel)

        self.PortLine = QLineEdit(self.frame_11)
        self.PortLine.setText("15672")  # Default RabbitMQ Management port
        self.horizontalLayout_5.addWidget(self.PortLine)

        self.gridLayout_2.addWidget(self.frame_11, 0, 0, 1, 1)

        # TCP/SSL toggle button frame
        self.frame_12 = QFrame(self.frame_10)
        self.frame_12.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_6 = QHBoxLayout(self.frame_12)
        self.horizontalLayout_6.setContentsMargins(0, 0, 0, 0)

        self.ProtocolLabel = QLabel(self.frame_12)
        self.ProtocolLabel.setText("Protocol:")
        self.horizontalLayout_6.addWidget(self.ProtocolLabel)

        self.ProtocolToggleButton = QPushButton(self.frame_12)
        self.ProtocolToggleButton.setText("TCP")
        self.horizontalLayout_6.addWidget(self.ProtocolToggleButton)

        self.gridLayout_2.addWidget(self.frame_12, 1, 0, 1, 1)

        self.horizontalLayout_3.addWidget(self.frame_10)
        self.verticalLayout_3.addWidget(self.frame_8)

        self.verticalLayout_3.addSpacerItem(QSpacerItem(0, 1, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Main content frame
        self.frame_3 = QFrame(widget)
        self.gridLayout = QGridLayout(self.frame_3)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)

        # Set column stretch to make HostsTextBox ~20% and OutputTable ~80%
        self.gridLayout.setColumnStretch(0, 4)  # Hosts column (~20%)
        self.gridLayout.setColumnStretch(1, 16)  # Output column (~80%)

        # Hosts controls
        self.frame = QFrame(self.frame_3)
        self.frame.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout = QHBoxLayout(self.frame)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)

        self.HostsLabel = QLabel(self.frame)
        self.horizontalLayout.addWidget(self.HostsLabel)

        self.HostsClearButton = QPushButton(self.frame)
        self.HostsClearButton.setText("Clear")
        self.horizontalLayout.addWidget(self.HostsClearButton)

        self.HostsLoadButton = QPushButton(self.frame)
        self.horizontalLayout.addWidget(self.HostsLoadButton)

        self.HostsSaveButton = QPushButton(self.frame)
        self.HostsSaveButton.setText("Save")
        self.horizontalLayout.addWidget(self.HostsSaveButton)

        self.HostsSortDedupButton = QPushButton(self.frame)
        self.HostsSortDedupButton.setText("Sort+Dedup")
        self.horizontalLayout.addWidget(self.HostsSortDedupButton)

        self.horizontalSpacer_3 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout.addItem(self.horizontalSpacer_3)

        self.gridLayout.addWidget(self.frame, 0, 0, 1, 1)

        # Output controls
        self.frame_2 = QFrame(self.frame_3)
        self.frame_2.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_2 = QHBoxLayout(self.frame_2)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)

        self.OutputLabel = QLabel(self.frame_2)
        self.horizontalLayout_2.addWidget(self.OutputLabel)

        self.OutputClearButton = QPushButton(self.frame_2)
        self.OutputClearButton.setText("Clear")
        self.horizontalLayout_2.addWidget(self.OutputClearButton)

        self.OutputSaveButton = QPushButton(self.frame_2)
        self.horizontalLayout_2.addWidget(self.OutputSaveButton)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.ScanButton = QPushButton(self.frame_2)
        font1 = QFont()
        font1.setBold(True)
        self.ScanButton.setFont(font1)
        self.horizontalLayout_2.addWidget(self.ScanButton)

        self.gridLayout.addWidget(self.frame_2, 0, 1, 1, 1)

        # Text boxes
        self.HostsTextBox = QPlainTextEdit(self.frame_3)
        self.gridLayout.addWidget(self.HostsTextBox, 1, 0, 1, 1)

        # Output table
        self.OutputTable = QTableWidget(self.frame_3)
        self.OutputTable.setColumnCount(7)  # Updated to 7 columns
        self.OutputTable.setHorizontalHeaderLabels(["Timestamp", "Hostname", "Port", "Defaults", "Auth Status", "Version", "Users"])
        self.OutputTable.setEditTriggers(QTableWidget.NoEditTriggers)  # Make read-only
        self.OutputTable.horizontalHeader().setSortIndicatorShown(True)  # Show sort indicator
        self.gridLayout.addWidget(self.OutputTable, 1, 1, 1, 1)

        self.verticalLayout_3.addWidget(self.frame_3)

        # Status frame
        self.frame_4 = QFrame(widget)
        self.frame_4.setFrameShape(QFrame.NoFrame)
        self.verticalLayout = QVBoxLayout(self.frame_4)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)

        self.StatusTextBox = QPlainTextEdit(self.frame_4)
        self.StatusTextBox.setReadOnly(True)
        self.verticalLayout.addWidget(self.StatusTextBox)

        self.verticalLayout_3.addWidget(self.frame_4)

        # Adjust spacing
        self.gridLayout.setVerticalSpacing(0)
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout_2.setSpacing(0)

        self.retranslateUi(widget)

    def retranslateUi(self, widget):
        self.label_3.setText(f"""
 _____     _   _   _ _   _ _ _ _____ _____                 
| __  |___| |_| |_|_| |_| | | |   __| __  |___ ___ ___ ___ 
|    -| .'| . | . | |  _| | | |   __| __ -|_ -|  _| .'|   |
|__|__|__,|___|___|_|_| |_____|_____|_____|___|___|__,|_|_|

 Version: {VERSION}""")
        self.PortLabel.setText("Port:")
        self.HostsLabel.setText("Hosts:  ")
        self.HostsLoadButton.setText("Load")
        self.HostsSaveButton.setText("Save")
        self.HostsSortDedupButton.setText("Sort+Dedup")
        self.OutputLabel.setText("Output:  ")
        self.OutputSaveButton.setText("Save")
        self.OutputClearButton.setText("Clear")
        self.ScanButton.setText("Scan")

class TabContent(QWidget):
    def __init__(self):
        """Initialize the TabContent widget with custom adjustments."""
        super().__init__()
        self.ui = Ui_TabContent()
        self.ui.setupUi(self)

        # Initialize protocol state (True for TCP, False for SSL)
        self.is_tcp = True

        # Additional UI adjustments
        spacer_port = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_5.insertSpacerItem(0, spacer_port)

        spacer_protocol = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_6.insertSpacerItem(0, spacer_protocol)

        self.ui.HostsLoadButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.HostsClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.HostsSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.HostsSortDedupButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.OutputSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.OutputClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ScanButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ProtocolToggleButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        self.ui.OutputTable.setRowCount(0)  # Initialize empty table
        self.ui.OutputTable.setSortingEnabled(True)  # Enable column sorting

        # Apply stylesheet for table header borders
        self.ui.OutputTable.setStyleSheet("""
            QHeaderView::section:horizontal {
                border: 1px solid black;
                padding: 4px;
            }
        """)

        # Set PortLine width to match ProtocolToggleButton
        button_width = self.ui.ProtocolToggleButton.size().width()
        self.ui.PortLine.setFixedWidth(button_width)

        # Initialize OutputTable with headers
        self.set_csv_header()

        # Connect signals to slots
        self.ui.HostsLoadButton.clicked.connect(self.load_hosts)
        self.ui.HostsClearButton.clicked.connect(self.clear_hosts)
        self.ui.HostsSaveButton.clicked.connect(self.save_hosts)
        self.ui.HostsSortDedupButton.clicked.connect(self.sort_dedup_hosts)
        self.ui.OutputSaveButton.clicked.connect(self.save_output)
        self.ui.OutputClearButton.clicked.connect(self.clear_output)
        self.ui.ProtocolToggleButton.clicked.connect(self.toggle_protocol)
        self.ui.ScanButton.clicked.connect(self.scan_hosts)
        self.ui.PortLine.returnPressed.connect(self.scan_hosts)

    def showEvent(self, event):
        """Override the showEvent to set focus to the PortLine when the tab is shown."""
        super().showEvent(event)
        self.ui.PortLine.setFocus()

    def toggle_protocol(self):
        """Toggle between TCP and SSL protocol."""
        self.is_tcp = not self.is_tcp
        self.ui.ProtocolToggleButton.setText("TCP" if self.is_tcp else "SSL")
        self.ui.StatusTextBox.appendPlainText(f"\nProtocol set to: {'TCP' if self.is_tcp else 'SSL'}")

    def load_hosts(self):
        """Load hosts from a file into the HostsTextBox."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Load Hosts", "", "All Files (*);;Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    self.ui.HostsTextBox.setPlainText(f.read())
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error loading file: {e}")

    def clear_hosts(self):
        """Clear the contents of the HostsTextBox."""
        self.ui.HostsTextBox.clear()

    def save_hosts(self):
        """Save the contents of the HostsTextBox to a file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Hosts", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            if not file_name.lower().endswith('.txt'):
                file_name += '.txt'
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.ui.HostsTextBox.toPlainText())
                self.ui.StatusTextBox.appendPlainText(f"\nHosts saved to {file_name}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving hosts file: {e}")

    def sort_dedup_hosts(self):
        """Sort and deduplicate the lines in the HostsTextBox, sorting IPs numerically and hostnames alphabetically after IPs."""
        hosts = [h.strip() for h in self.ui.HostsTextBox.toPlainText().splitlines() if h.strip()]
        if not hosts:
            self.ui.StatusTextBox.appendPlainText("\nNo hosts to sort or deduplicate.")
            return

        def host_sort_key(host):
            try:
                octets = host.split('.')
                if len(octets) == 4 and all(o.isdigit() and 0 <= int(o) <= 255 for o in octets):
                    return (0, tuple(int(o) for o in octets))
            except ValueError:
                pass
            return (1, host.lower())

        unique_hosts = sorted(set(hosts), key=host_sort_key)
        sorted_text = '\n'.join(unique_hosts)
        self.ui.HostsTextBox.setPlainText(sorted_text)
        self.ui.StatusTextBox.appendPlainText(f"\nSorted and deduplicated {len(hosts)} hosts to {len(unique_hosts)} unique hosts.")

    def save_output(self):
        """Save the contents of the OutputTable to a CSV file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Output", "", "CSV Files (*.csv);;All Files (*)")
        if file_name:
            if not file_name.lower().endswith('.csv'):
                file_name += '.csv'
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    writer = csv.writer(f, delimiter="|", quoting=csv.QUOTE_MINIMAL)
                    header = ["Timestamp", "Hostname", "Port", "Defaults", "Auth Status", "Version", "Users"]
                    writer.writerow(header)
                    for row in range(self.ui.OutputTable.rowCount()):
                        row_data = []
                        for col in range(self.ui.OutputTable.columnCount()):
                            item = self.ui.OutputTable.item(row, col)
                            row_data.append(item.text() if item else "")
                        writer.writerow(row_data)
                self.ui.StatusTextBox.appendPlainText(f"\nOutput saved to {file_name}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving file: {e}")

    def clear_output(self):
        """Clear the contents of the OutputTable and reset headers."""
        self.ui.OutputTable.setRowCount(0)
        self.set_csv_header()

    def set_csv_header(self):
        """Initialize the OutputTable with column headers and widths."""
        self.ui.OutputTable.setRowCount(0)
        self.ui.OutputTable.setColumnCount(7)  # 7 columns
        self.ui.OutputTable.setHorizontalHeaderLabels(["Timestamp", "Hostname", "Port", "Defaults", "Auth Status", "Version", "Users"])
        self.ui.OutputTable.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ui.OutputTable.setColumnWidth(0, 160)  # Timestamp
        self.ui.OutputTable.setColumnWidth(1, 130)  # Hostname
        self.ui.OutputTable.setColumnWidth(2, 90)   # Port
        self.ui.OutputTable.setColumnWidth(3, 150)  # Defaults
        self.ui.OutputTable.setColumnWidth(4, 90)   # Auth Status
        self.ui.OutputTable.setColumnWidth(5, 100)  # Version
        self.ui.OutputTable.setColumnWidth(6, 200)  # Users
        self.ui.OutputTable.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)

    def scan_hosts(self):
        """Scan each host in the HostsTextBox for RabbitMQ Management API details."""
        self.clear_output()

        port_input = self.ui.PortLine.text().strip()
        try:
            port = int(port_input)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535")
        except ValueError as e:
            self.ui.StatusTextBox.appendPlainText(f"Error: Invalid port number: {e}")
            return

        protocol = "tcp" if self.is_tcp else "ssl"
        port_display = f"{port}/{protocol}"

        hosts = [h.strip() for h in self.ui.HostsTextBox.toPlainText().splitlines() if h.strip()]
        if not hosts:
            self.ui.StatusTextBox.appendPlainText("Error: No hosts provided")
            return

        self.ui.StatusTextBox.appendPlainText(f"Starting scan for {len(hosts)} hosts on {port_display}...")

        for host in hosts:
            self.ui.StatusTextBox.appendPlainText(f"\nScanning {host}:{port_display}/api...")
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                defaults, auth_status, version, users = self.scan_host(host, port, protocol)
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error scanning {host}: {e}")
                defaults = "N/A"
                auth_status = "unknown"
                version = "unknown"
                users = "error"

            # Log the result even if an error occurred
            row_count = self.ui.OutputTable.rowCount()
            self.ui.OutputTable.insertRow(row_count)
            self.ui.OutputTable.scrollToBottom()
            row_data = [timestamp, host, port_display, defaults, auth_status, version, users]
            for col, data in enumerate(row_data):
                item = QTableWidgetItem(str(data))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                if col in [0, 1, 2, 3, 4, 5]:
                    item.setTextAlignment(Qt.AlignCenter)
                if col == 0:
                    try:
                        dt = datetime.datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                        item.setData(Qt.UserRole, dt)
                    except ValueError:
                        pass
                self.ui.OutputTable.setItem(row_count, col, item)
                QApplication.processEvents() # Force UI update

            self.ui.StatusTextBox.appendPlainText(f"Completed scan for {host}")

        self.ui.StatusTextBox.appendPlainText("\nScan completed.")

    def load_credentials(self):
        """Load username:password pairs from modules/rabbit-web-defaults.txt."""
        credentials_file = os.path.join("modules", "rabbit-web-defaults.txt")
        credentials = []
        try:
            if not os.path.exists(credentials_file):
                self.ui.StatusTextBox.appendPlainText(f"Error: Credentials file not found: {credentials_file}")
                return None
            with open(credentials_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and ':' in line:
                        username, password = line.split(':', 1)
                        credentials.append((username, password))
            self.ui.StatusTextBox.appendPlainText(f"Loaded {len(credentials)} credentials from {credentials_file}")
            return credentials
        except Exception as e:
            self.ui.StatusTextBox.appendPlainText(f"Error reading credentials file {credentials_file}: {e}")
            return None

    def scan_host(self, host, port, protocol):
        """Scan a single host for RabbitMQ Management API details."""
        defaults = "N/A"
        auth_status = "unknown"
        version = "unknown"
        users = "unknown"

        # Set protocol (HTTP or HTTPS)
        proto = "http" if protocol == "tcp" else "https"
        base_url = f"{proto}://{host}:{port}/api"
        session = requests.Session()
        session.verify = False  # Disable SSL verification for HTTPS (as per original SSL context)

        try:
            # Load credentials
            credentials = self.load_credentials()
            if credentials is None:
                defaults = "error"
                auth_status = "enabled"
                version = "no credentials file"
                users = "no credentials file"
                return defaults, auth_status, version, users

            # Try each credential pair
            for username, password in credentials:
                self.ui.StatusTextBox.appendPlainText(f"Testing credential: {username}:{password}")
                try:
                    # Check /api/whoami to verify authentication
                    response = session.get(
                        f"{base_url}/whoami",
                        auth=HTTPBasicAuth(username, password),
                        timeout=5
                    )
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("name") == username and "administrator" in data.get("tags", []):
                            auth_status = "bypassed"
                            self.ui.StatusTextBox.appendPlainText(f"Authentication successful with {username}:{password}")

                            # Initialize defaults with the successful credential
                            defaults_parts = [f"{username}:{password}"]
                            users_parts = [f""]

                            # Get version from /api/overview
                            try:
                                overview_response = session.get(
                                    f"{base_url}/overview",
                                    auth=HTTPBasicAuth(username, password),
                                    timeout=5
                                )
                                if overview_response.status_code == 200:
                                    version = overview_response.json().get("management_version", "Unknown")
                                    self.ui.StatusTextBox.appendPlainText(f"RabbitMQ Management Version: {version}")
                                else:
                                    self.ui.StatusTextBox.appendPlainText(f"Error retrieving version: HTTP {overview_response.status_code}")
                                    version = "error"
                            except Exception as e:
                                self.ui.StatusTextBox.appendPlainText(f"Error retrieving version: {e}")
                                version = "error"

                            # Get users from /api/users to include hash and role
                            try:
                                users_response = session.get(
                                    f"{base_url}/users",
                                    auth=HTTPBasicAuth(username, password),
                                    timeout=5
                                )
                                if users_response.status_code == 200:
                                    users_data = users_response.json()
                                    for user in users_data:
                                        name = user.get("name", "Unknown")
                                        password_hash = user.get("password_hash", "None")
                                        tags = user.get("tags", [])
                                        role = "administrator" if "administrator" in tags else "user"
                                        users_parts.append(f"User: {name}, Hash: {password_hash}, Role: {role}")
                                        self.ui.StatusTextBox.appendPlainText(f" - User: {name}, Hash: {password_hash}, Role: {role}")
                                else:
                                    self.ui.StatusTextBox.appendPlainText(f"Error retrieving users: HTTP {users_response.status_code}")
                            except Exception as e:
                                self.ui.StatusTextBox.appendPlainText(f"Error retrieving users: {e}")

                            # Set Defaults column
                            defaults = ";".join(defaults_parts)
                            users = "".join(users_parts)

                            break  # Stop after successful authentication
                        else:
                            self.ui.StatusTextBox.appendPlainText(f"Credential {username}:{password} valid but not administrator")
                    else:
                        self.ui.StatusTextBox.appendPlainText(f"Credential failed: {username}:{password} (HTTP {response.status_code})")
                except requests.exceptions.RequestException as e:
                    self.ui.StatusTextBox.appendPlainText(f"Error testing credential {username}:{password}: {e}")
                    if "connect" in str(e).lower():
                        users = "port not open"
                        raise Exception(f"Connection error: {e}")

            if auth_status != "bypassed":
                defaults = "None"
                auth_status = "enabled"
                version = "no valid credentials"
                users = "no valid credentials"
                self.ui.StatusTextBox.appendPlainText("No default credentials worked.")

        except Exception as e:
            self.ui.StatusTextBox.appendPlainText(f"Connection error: {e}")
            if "connect" in str(e).lower():
                users = "port not open"
            else:
                users = "error"
            raise Exception(f"Connection error: {e}")
        finally:
            session.close()

        return defaults, auth_status, version, users

if __name__ == "__main__":
    from PySide6.QtWidgets import QApplication
    import sys
    app = QApplication(sys.argv)
    widget = TabContent()
    widget.show()
    sys.exit(app.exec())
