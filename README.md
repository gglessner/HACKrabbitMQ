# HACKrabbitMQ

**rabbitWEBscan** is a tool designed for security professionals and administrators to scan RabbitMQ Management Web Interfaces. This module is part of the **HACKrabbitMQ Suite**, built to identify potential security vulnerabilities in RabbitMQ deployments.

## Features

- **Host Scanning**: Scan multiple RabbitMQ servers to check for open ports, default credentials, and security flaws.
- **Credential Testing**: Tests multiple credential pairs to check for unauthorized access.
- **Protocol Toggle**: Choose between TCP or SSL protocols for scanning.
- **User & Queue Information**: Retrieve information about users and queues from the RabbitMQ Management API.
- **CSV Export**: Export the scan results to CSV for further analysis.
- **Sorting & Deduplication**: Automatically sorts and removes duplicate host entries before scanning.

## Requirements

- Python 3.6+
- PySide6
- requests

To install the required dependencies, run the following:

```bash
pip install -r requirements.txt
````

## Installation

1. Clone this repository or download the source code.
2. Install dependencies using the command above.
3. Run the application via the HACKrabbit interface.

## Usage

* **Hosts**: Enter a list of RabbitMQ server hostnames or IPs to scan.
* **Port**: Default is 15672 (RabbitMQ Management port). You can change it as needed.
* **Protocol**: Toggle between TCP and SSL to suit your configuration.
* **Scan**: Click the **Scan** button to begin the process. Results are displayed in a table and can be saved to a CSV file.

### Scanning Process:

* The tool scans each provided host for the RabbitMQ Management API.
* It will test default credentials from the `rabbit-web-defaults.txt` file and check if authentication can be bypassed.
* For each host, details about the server's version, queues, and users will be retrieved.
* The results are displayed in the output table, where you can see the timestamp, hostname, port, authentication status, RabbitMQ version, and queues.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).

## Contact

For any questions or suggestions, feel free to contact the author: Garland Glessner ([gglesner@gmail.com](mailto:gglesner@gmail.com)).
