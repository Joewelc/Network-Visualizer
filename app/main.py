import tkinter as tk
from tkinter import ttk
from tkinter import simpledialog, messagebox
from scapy.all import srp, Ether, ARP
import threading
import netifaces

class NetworkVisualizerApp(tk.Tk):
    """
    Network Visualizer Application using Tkinter and Scapy.
    """

    def __init__(self):
        super().__init__()

        # Set a dark background color for the main GUI window
        self.configure(bg='#2E2E2E')

        self.title("JW's Network Visualizer")
        self.geometry("400x300")

        # Define a style for the scrollbar
        style = ttk.Style()
        style.theme_use('aqua')
        style.configure("Custom.Vertical.TScrollbar", background="#555555")
        style.layout("Custom.Vertical.TScrollbar", [
            ("Vertical.Scrollbar.trough", {"children": [
                ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "ns"})
            ], "sticky": "ns"})
        ])

        # Adding widgets with a dark background
        self.label = ttk.Label(self, text="Network Devices:", background='#2E2E2E', foreground='#FFFFFF')
        self.label.pack()

        self.scrollbar = ttk.Scrollbar(self, orient="vertical", style="Custom.Vertical.TScrollbar")
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.listbox = tk.Listbox(self, yscrollcommand=self.scrollbar.set, bg="#2E2E2E", fg="#FFFFFF")
        self.listbox.pack(fill=tk.BOTH, expand=1)

        self.scrollbar.config(command=self.listbox.yview)

        self.scan_button = ttk.Button(self, text="Scan", command=self.start_scan)
        self.scan_button.pack()

        self.exit_button = ttk.Button(self, text="Exit", command=self.quit)
        self.exit_button.pack()

    def get_subnet(self):
        """
        Get the local subnet in CIDR notation.
        """
        # Get default gateway
        gws = netifaces.gateways()
        default_gateway = gws.get('default')
        if default_gateway:
            default_interface = default_gateway.get(netifaces.AF_INET)[1]
            # Get IP information
            ip_info = netifaces.ifaddresses(default_interface).get(netifaces.AF_INET)[0]

            # Convert netmask to CIDR
            netmask = ip_info['netmask']
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])

            subnet = f"{ip_info['addr']}/{cidr}"
            print(f"Detected Subnet in CIDR notation: {subnet}")  # Debugging print
            return subnet

    def scan(self, ip):
        """
        Scan the network for devices.
        """
        print(f"Scanning: {ip}")  # Debugging print
        try:
            # ARP request to get MAC addresses
            request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(request, timeout=2, verbose=0)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            return

        for _, packet in ans:
            ip_addr = packet.psrc
            mac_addr = packet.hwsrc

            # Update the listbox in the GUI
            self.listbox.insert(tk.END, f"IP: {ip_addr}, MAC: {mac_addr}")

        devices = []
        for _, packet in ans:
            ip_addr = packet.psrc
            mac_addr = packet.hwsrc

    def scan_network(self):
        """
        Populate the listbox with devices found on the network.
        """
        subnet = self.get_subnet()
        if subnet:
            devices = self.scan(subnet)
            for device in devices:
                self.listbox.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, OS: {device['os']}")

    def start_scan(self):
        """
        Start scanning in a non-blocking manner.
        """
        # Run scan_network method in a separate thread
        threading.Thread(target=self.scan_network, daemon=True).start()

if __name__ == "__main__":
    app = NetworkVisualizerApp()
    app.mainloop()
