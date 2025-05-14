# RabbitAPI - part of the HACKrabbitMQ Suite
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

from PySide6.QtWidgets import QWidget, QPlainTextEdit, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QFrame, QGridLayout, QFileDialog, QSpacerItem, QSizePolicy, QComboBox
from PySide6.QtGui import QFont
from PySide6.QtCore import Qt
import datetime
import os
import requests
from requests.auth import HTTPBasicAuth
import json

# Define the version number at the top
VERSION = "1.0.0"

# Define the tab label for the tab widget
TAB_LABEL = f"RabbitAPI v{VERSION}"

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

        # IP address input frame
        self.frame_ip = QFrame(self.frame_10)
        self.frame_ip.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_ip = QHBoxLayout(self.frame_ip)
        self.horizontalLayout_ip.setContentsMargins(0, 0, 0, 0)

        self.IpLabel = QLabel(self.frame_ip)
        self.IpLabel.setText("IP Address:")
        self.horizontalLayout_ip.addWidget(self.IpLabel)

        self.IpLine = QLineEdit(self.frame_ip)
        self.IpLine.setPlaceholderText("Enter IP address")
        self.horizontalLayout_ip.addWidget(self.IpLine)

        self.gridLayout_2.addWidget(self.frame_ip, 0, 0, 1, 1)

        # Port input frame
        self.frame_11 = QFrame(self.frame_10)
        self.frame_11.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_5 = QHBoxLayout(self.frame_11)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)

        self.PortLabel = QLabel(self.frame_11)
        self.PortLabel.setText("Port:")
        self.horizontalLayout_5.addWidget(self.PortLabel)

        self.PortLine = QLineEdit(self.frame_11)
        self.PortLine.setText("15672")  # Default RabbitMQ Management port
        self.horizontalLayout_5.addWidget(self.PortLine)

        self.gridLayout_2.addWidget(self.frame_11, 1, 0, 1, 1)

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

        self.gridLayout_2.addWidget(self.frame_12, 2, 0, 1, 1)

        # Method dropdown frame
        self.frame_method = QFrame(self.frame_10)
        self.frame_method.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_method = QHBoxLayout(self.frame_method)
        self.horizontalLayout_method.setContentsMargins(0, 0, 0, 0)

        self.MethodLabel = QLabel(self.frame_method)
        self.MethodLabel.setText("Method:")
        self.horizontalLayout_method.addWidget(self.MethodLabel)

        self.MethodComboBox = QComboBox(self.frame_method)
        self.MethodComboBox.addItems(["GET", "PUT", "DELETE"])
        self.horizontalLayout_method.addWidget(self.MethodComboBox)

        self.gridLayout_2.addWidget(self.frame_method, 3, 0, 1, 1)

        self.horizontalLayout_3.addWidget(self.frame_10)
        self.verticalLayout_3.addWidget(self.frame_8)

        self.verticalLayout_3.addSpacerItem(QSpacerItem(0, 1, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Main content frame
        self.frame_3 = QFrame(widget)
        self.gridLayout = QGridLayout(self.frame_3)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)

        # Set column stretch to make RequestTextBox ~20% and ResponseTextBox ~80%
        self.gridLayout.setColumnStretch(0, 8)  # Request column (~50%)
        self.gridLayout.setColumnStretch(1, 8)  # Response column (~50%)

        # Request controls
        self.frame = QFrame(self.frame_3)
        self.frame.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout = QHBoxLayout(self.frame)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)

        self.RequestLabel = QLabel(self.frame)
        self.RequestLabel.setText("Request Body:  ")
        self.horizontalLayout.addWidget(self.RequestLabel)

        self.RequestClearButton = QPushButton(self.frame)
        self.RequestClearButton.setText("Clear")
        self.horizontalLayout.addWidget(self.RequestClearButton)

        self.RequestLoadButton = QPushButton(self.frame)
        self.RequestLoadButton.setText("Load")
        self.horizontalLayout.addWidget(self.RequestLoadButton)

        self.RequestSaveButton = QPushButton(self.frame)
        self.RequestSaveButton.setText("Save")
        self.horizontalLayout.addWidget(self.RequestSaveButton)

        self.horizontalSpacer_3 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout.addItem(self.horizontalSpacer_3)

        self.gridLayout.addWidget(self.frame, 0, 0, 1, 1)

        # Response controls
        self.frame_2 = QFrame(self.frame_3)
        self.frame_2.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_2 = QHBoxLayout(self.frame_2)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)

        self.ResponseLabel = QLabel(self.frame_2)
        self.ResponseLabel.setText("Response:  ")
        self.horizontalLayout_2.addWidget(self.ResponseLabel)

        self.ResponseClearButton = QPushButton(self.frame_2)
        self.ResponseClearButton.setText("Clear")
        self.horizontalLayout_2.addWidget(self.ResponseClearButton)

        self.ResponseSaveButton = QPushButton(self.frame_2)
        self.ResponseSaveButton.setText("Save")
        self.horizontalLayout_2.addWidget(self.ResponseSaveButton)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        # API endpoint dropdown and parameter input
        self.ApiEndpointLabel = QLabel(self.frame_2)
        self.ApiEndpointLabel.setText("API Endpoint:")
        self.horizontalLayout_2.addWidget(self.ApiEndpointLabel)

        self.ApiEndpointComboBox = QComboBox(self.frame_2)
        self.ApiEndpointComboBox.addItems(["whoami", "overview", "cluster-name", "nodes", "nodes/", "definitions", "definitions/", "feature-flags", "deprecated-features", "deprecated-features/used", "connections", "connections/", "connections/username/", "vhosts", "vhosts/", "channels", "channels/", "consumers", "consumers/", "exchanges", "exchanges/", "queues", "queues/", "queues/detailed", "bindings", "bindings/", "users", "users/", "users/without-permissions", "users/bulk-delete", "users/user-limits", "users/user-limits/", "permissions", "permissions/", "topic-permissions", "topic-permissions/", "parameters", "parameters/", "global-parameters", "global-parameters/", "policies", "policies/", "operator-policies", "operator-policies/", "vhost-limits", "vhost-limits/", "federation-links", "federation-links/", "auth", "auth/attempts/", "auth/hash_password/", "stream/connections", "stream/connections/", "stream/publishers", "stream/publishers/", "stream/consumers", "stream/consumers/", "health/checks/alarms", "health/checks/local-alarms", "health/checks/certificate-expiration/", "health/checks/port-listener/", "health/checks/protocol-listener/", "health/checks/virtual-hosts", "health/checks/node-is-quorum-critical", "health/checks/is-in-service", "health/checks/below-node-connection-limit", "health/checks/ready-to-serve-clients", "rebalance/queues"])
        self.horizontalLayout_2.addWidget(self.ApiEndpointComboBox)

        self.ApiParamLine = QLineEdit(self.frame_2)
        self.ApiParamLine.setPlaceholderText("Enter parameter (e.g., username or node)")
        self.ApiParamLine.setEnabled(False)  # Disabled by default
        self.horizontalLayout_2.addWidget(self.ApiParamLine)

        self.SubmitButton = QPushButton(self.frame_2)
        font1 = QFont()
        font1.setBold(True)
        self.SubmitButton.setFont(font1)
        self.SubmitButton.setText("Submit")
        self.horizontalLayout_2.addWidget(self.SubmitButton)

        self.gridLayout.addWidget(self.frame_2, 0, 1, 1, 1)

        # Text boxes
        self.RequestTextBox = QPlainTextEdit(self.frame_3)
        self.gridLayout.addWidget(self.RequestTextBox, 1, 0, 1, 1)

        self.ResponseTextBox = QPlainTextEdit(self.frame_3)
        self.ResponseTextBox.setReadOnly(True)
        self.gridLayout.addWidget(self.ResponseTextBox, 1, 1, 1, 1)

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
 _____     _   _   _ _   _____ _____ _____ 
| __  |___| |_| |_|_| |_|  _  |  _  |     |
|    -| .'| . | . | |  _|     |   __|-   -|
|__|__|__,|___|___|_|_| |__|__|__|  |_____|

 Version: {VERSION}""")
        self.IpLabel.setText("IP Address:")
        self.PortLabel.setText("Port:")
        self.RequestLabel.setText("Request Body:  ")
        self.RequestLoadButton.setText("Load")
        self.RequestSaveButton.setText("Save")
        self.ResponseLabel.setText("Response:  ")
        self.ResponseSaveButton.setText("Save")
        self.ResponseClearButton.setText("Clear")
        self.SubmitButton.setText("Submit")

class TabContent(QWidget):
    def __init__(self):
        """Initialize the TabContent widget with custom adjustments."""
        super().__init__()
        self.ui = Ui_TabContent()
        self.ui.setupUi(self)

        # Initialize protocol state (True for TCP, False for SSL)
        self.is_tcp = True

        # Additional UI adjustments
        spacer_ip = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_ip.insertSpacerItem(0, spacer_ip)

        spacer_port = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_5.insertSpacerItem(0, spacer_port)

        spacer_protocol = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_6.insertSpacerItem(0, spacer_protocol)

        spacer_method = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_method.insertSpacerItem(0, spacer_method)

        self.ui.RequestLoadButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.RequestClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.RequestSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ResponseSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ResponseClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.SubmitButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ProtocolToggleButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.MethodComboBox.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.ApiEndpointComboBox.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        # Set IpLine and PortLine width to match ProtocolToggleButton
        button_width = self.ui.ProtocolToggleButton.sizeHint().width()
        self.ui.IpLine.setFixedWidth(button_width * 2)  # Wider for IP address
        self.ui.PortLine.setFixedWidth(button_width)
        self.ui.MethodComboBox.setFixedWidth(button_width * 2)
        self.ui.ApiEndpointComboBox.setFixedWidth(button_width * 3)  # Wider for endpoints
        self.ui.ApiParamLine.setFixedWidth(button_width * 4)  # Wider for parameters

        # Connect signals to slots
        self.ui.RequestLoadButton.clicked.connect(self.load_request)
        self.ui.RequestClearButton.clicked.connect(self.clear_request)
        self.ui.RequestSaveButton.clicked.connect(self.save_request)
        self.ui.ResponseSaveButton.clicked.connect(self.save_response)
        self.ui.ResponseClearButton.clicked.connect(self.clear_response)
        self.ui.ProtocolToggleButton.clicked.connect(self.toggle_protocol)
        self.ui.SubmitButton.clicked.connect(self.submit_request)
        self.ui.IpLine.returnPressed.connect(self.submit_request)
        self.ui.PortLine.returnPressed.connect(self.submit_request)
        self.ui.ApiEndpointComboBox.currentTextChanged.connect(self.update_api_param)

        # Initial update of API parameter field
        self.update_api_param(self.ui.ApiEndpointComboBox.currentText())

    def showEvent(self, event):
        """Override the showEvent to set focus to the IpLine when the tab is shown."""
        super().showEvent(event)
        self.ui.IpLine.setFocus()

    def toggle_protocol(self):
        """Toggle between TCP and SSL protocol."""
        self.is_tcp = not self.is_tcp
        self.ui.ProtocolToggleButton.setText("TCP" if self.is_tcp else "SSL")
        self.ui.StatusTextBox.appendPlainText(f"\nProtocol set to: {'TCP' if self.is_tcp else 'SSL'}")

    def update_api_param(self, endpoint):
        """Enable or disable the API parameter input based on endpoint."""
        self.ui.ApiParamLine.setEnabled(endpoint.endswith('/'))
        if endpoint.endswith('/'):
            if endpoint == "user/":
                self.ui.ApiParamLine.setPlaceholderText("Enter username")
            elif endpoint == "node/":
                self.ui.ApiParamLine.setPlaceholderText("Enter node name")
            else:
                self.ui.ApiParamLine.setPlaceholderText("Enter parameter")
        else:
            self.ui.ApiParamLine.setPlaceholderText("")

    def load_request(self):
        """Load request body from a file into the RequestTextBox."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Load Request", "", "All Files (*);;Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    self.ui.RequestTextBox.setPlainText(f.read())
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error loading file: {e}")

    def clear_request(self):
        """Clear the contents of the RequestTextBox."""
        self.ui.RequestTextBox.clear()

    def save_request(self):
        """Save the contents of the RequestTextBox to a file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Request", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            if not file_name.lower().endswith('.txt'):
                file_name += '.txt'
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.ui.RequestTextBox.toPlainText())
                self.ui.StatusTextBox.appendPlainText(f"\nRequest saved to {file_name}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving request file: {e}")

    def save_response(self):
        """Save the contents of the ResponseTextBox to a file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Response", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            if not file_name.lower().endswith('.txt'):
                file_name += '.txt'
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.ui.ResponseTextBox.toPlainText())
                self.ui.StatusTextBox.appendPlainText(f"\nResponse saved to {file_name}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving response file: {e}")

    def clear_response(self):
        """Clear the contents of the ResponseTextBox."""
        self.ui.ResponseTextBox.clear()

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

    def submit_request(self):
        """Submit a single web request based on user inputs."""
        self.clear_response()

        # Validate IP address
        ip = self.ui.IpLine.text().strip()
        if not ip:
            self.ui.StatusTextBox.appendPlainText("Error: No IP address provided")
            return

        # Validate port
        port_input = self.ui.PortLine.text().strip()
        try:
            port = int(port_input)
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535")
        except ValueError as e:
            self.ui.StatusTextBox.appendPlainText(f"Error: Invalid port number: {e}")
            return

        # Get protocol, method, endpoint, and parameter
        protocol = "tcp" if self.is_tcp else "ssl"
        method = self.ui.MethodComboBox.currentText()
        endpoint = self.ui.ApiEndpointComboBox.currentText()
        param = self.ui.ApiParamLine.text().strip() if endpoint.endswith('/') else ""

        # Build the URL
        proto = "http" if protocol == "tcp" else "https"
        api_path = f"{endpoint}{param}" if param else endpoint
        url = f"{proto}://{ip}:{port}/api/{api_path}"
        port_display = f"{port}/{protocol}"

        self.ui.StatusTextBox.appendPlainText(f"\nSubmitting {method} request to {url}...")

        # Load credentials
        credentials = self.load_credentials()
        if credentials is None:
            self.ui.StatusTextBox.appendPlainText("Error: No credentials available")
            self.ui.ResponseTextBox.setPlainText("Error: No credentials file")
            self.repaint()  # Update UI
            return

        # Get request body for PUT or DELETE
        body = self.ui.RequestTextBox.toPlainText().strip()
        try:
            body_data = json.loads(body) if body and method in ["PUT", "DELETE"] else None
        except json.JSONDecodeError as e:
            self.ui.StatusTextBox.appendPlainText(f"Error: Invalid JSON in request body: {e}")
            self.ui.ResponseTextBox.setPlainText(f"Error: Invalid JSON in request body: {e}")
            self.repaint()  # Update UI
            return

        # Initialize session
        session = requests.Session()
        session.verify = False  # Disable SSL verification for HTTPS

        response_text = ""
        success = False
        try:
            # Try each credential pair
            for username, password in credentials:
                self.ui.StatusTextBox.appendPlainText(f"Testing credential: {username}:{password}")
                try:
                    # Send the request
                    response = session.request(
                        method=method,
                        url=url,
                        auth=HTTPBasicAuth(username, password),
                        json=body_data if body_data else None,
                        timeout=5
                    )
                    self.ui.StatusTextBox.appendPlainText(f"Received HTTP {response.status_code}")
                    
                    # Format response
                    try:
                        # Try to parse JSON response
                        response_json = response.json()
                        response_text = json.dumps(response_json, indent=2)
                    except ValueError:
                        # Fallback to raw text if not JSON
                        response_text = response.text
                        
                    response_text = f"HTTP {response.status_code}\n\n{response_text}"
                    success = response.status_code in [200, 201, 204]
                    self.ui.StatusTextBox.appendPlainText(f"Request successful with {username}:{password}")
                    break  # Stop after successful request
                except requests.exceptions.RequestException as e:
                    self.ui.StatusTextBox.appendPlainText(f"Error with credential {username}:{password}: {e}")
                    if "connect" in str(e).lower():
                        response_text = f"Error: Connection failed: {e}"
                        break

            if not success:
                response_text = response_text or "Error: All credentials failed"
                self.ui.StatusTextBox.appendPlainText("No credentials worked.")

        except Exception as e:
            self.ui.StatusTextBox.appendPlainText(f"Unexpected error: {e}")
            response_text = f"Error: {e}"
        finally:
            session.close()

        # Update ResponseTextBox
        self.ui.ResponseTextBox.setPlainText(response_text)
        self.ui.StatusTextBox.appendPlainText("Request completed.")

        # Update QApplication display
        self.repaint()

if __name__ == "__main__":
    from PySide6.QtWidgets import QApplication
    import sys
    app = QApplication(sys.argv)
    widget = TabContent()
    widget.show()
    sys.exit(app.exec())
