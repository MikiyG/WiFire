WiFire - Network Control Tool

WiFire is an educational tool designed for network analysis and administration. It enables users to scan a network for connected devices, retrieve their IP and MAC addresses, and perform ARP spoofing for testing and security auditing purposes. The tool features a modern graphical user interface (GUI) built with Tkinter and leverages Scapy for packet manipulation.



https://github.com/MikiyG/WiFire/blob/master/WifirePic.png?raw=true


    ⚠️ Disclaimer: This tool is intended for ethical and educational use only. Unauthorized use on networks you do not own or have explicit permission to test is illegal and unethical.

Features

    Network Scanning: Discover devices on your network, including IP addresses, MAC addresses, and hostnames.
    ARP Spoofing: Perform ARP spoofing to simulate network attacks (for educational purposes).
    Graphical User Interface (GUI): Intuitive interface built with Tkinter for seamless interaction.
    Auto-Spoofing: Automatically spoof devices marked for auto-spoofing upon scanning.
    Configuration Management: Save and load target configurations for quick setup.
    Device Filtering: Search and filter devices by IP, MAC, or hostname.
    Cross-Platform: Compatible with Windows and Linux (requires administrative privileges).
    Logging: Real-time logs for monitoring tool activities.

Requirements

    Python 3.x
    Scapy: For packet manipulation and network scanning (pip install scapy).
    Netifaces: For retrieving network interface details (pip install netifaces).
    Tkinter: For the GUI (typically included with Python; install separately if needed).
    Administrative Privileges: Required for network operations like ARP spoofing.

Installation

    Clone the Repository:
    bash

git clone https://github.com/yourusername/wifire.git
cd wifire
Install Dependencies:
bash
pip install scapy netifaces

    Note: Tkinter is usually bundled with Python. If not, install it:

        On Linux: sudo apt-get install python3-tk
        On Windows: Ensure it’s included in your Python installation.

Run the Application:

    On Windows (run as Administrator):
    bash

python wifire.py
On Linux (run with sudo):
bash

        sudo python3 wifire.py

Usage

    Launch the Tool:
        Start the application with administrative privileges. The GUI will load with a default network interface (if detected).
    Select Network Interface:
        Choose your network interface from the dropdown menu (e.g., eth0, wlan0, or Ethernet).
        Click Apply to set the interface and retrieve gateway details.
    Scan the Network:
        Click Refresh to scan the network and list connected devices.
        The table displays device names, IP addresses, MAC addresses, and auto-spoof status.
    Filter Devices:
        Enter a search term (IP, MAC, or device name) in the search bar and click Filter to narrow down the list.
    Perform ARP Spoofing:
        Select one or more devices from the table.
        Set the spoofing interval (in seconds) in the "Spoofing Interval" field (default is 1).
        Click Start Spoofing to begin ARP spoofing. Spoofed devices will be marked as "(Spoofed)" in the table.
        Click Stop Spoofing to halt the attack and restore the network.
    Manage Auto-Spoofing:
        Select devices and click Mark Auto-Spoof to enable automatic spoofing on future scans.
        Click Unmark Auto-Spoof to remove devices from auto-spoofing.
        Auto-spoofed devices are saved to auto_spoof.json and spoofed automatically after each refresh.
    Save/Load Configurations:
        Select targets and click Save Config to save them to config.json.
        Click Load Config to reload previously saved targets.
    Monitor Activity:
        The log window on the right displays real-time updates (e.g., scanning results, spoofing status).

How It Works

    Network Scanning: Sends ARP requests to discover devices on the network, using Scapy for packet handling and multithreading for hostname resolution.
    ARP Spoofing: Sends spoofed ARP packets to associate the attacker's MAC address with the gateway’s IP, intercepting traffic between the target and gateway.
    GUI: Built with Tkinter and styled with the clam theme for a modern look, featuring a device table, log window, and control buttons.

Ethical Use

WiFire is designed for educational purposes to teach network security concepts like ARP spoofing and device discovery. Use it only on networks you own or have explicit permission to test. Unauthorized use may violate laws and result in legal consequences.
Troubleshooting

    No Devices Found:
        Ensure the correct network interface is selected and you’re connected to the network.
        Verify administrative privileges.
    Permission Errors:
        Run the tool as Administrator (Windows) or with sudo (Linux).
    Interface Not Found:
        Check if the network interface is active (ip link on Linux or ipconfig on Windows).
    Spoofing Fails:
        Confirm the gateway IP and MAC are correctly detected after applying the interface.

Contributing

Contributions are welcome! To contribute:

    Fork the repository.
    Create a feature branch (git checkout -b feature/your-feature).
    Commit your changes (git commit -m "Add your feature").
    Push to the branch (git push origin feature/your-feature).
    Open a pull request.

License

This project is licensed under the MIT License. See the  file for details.
