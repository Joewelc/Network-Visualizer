import tkinter as tk
from tkinter import ttk
from tkinter import simpledialog
from scapy.all import srp, Ether, ARP

class NetworkVisualizerApp(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Network Visualizer")
        self.geometry("400x300")

        self.label = ttk.Label(self, text="Network Devices:")
        self.label.pack()

        self.listbox = tk.Listbox(self)
        self.listbox.pack(fill=tk.BOTH, expand=1)

        self.scan_button = ttk.Button(self, text="Scan", command=self.scan_network)
        self.scan_button.pack()

        self.exit_button = ttk.Button(self, text="Exit", command=self.quit)
        self.exit_button.pack()

    def scan(self, ip):
        request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        ans, _ = srp(request, timeout=2, verbose=0)

        devices = []
        for _, packet in ans:
            devices.append({'ip': packet.psrc, 'mac': packet.hwsrc})

        return devices

    def scan_network(self):
        ip_range = simpledialog.askstring("Input", "Enter IP range (e.g. 192.168.1.1/24)",
                                          parent=self)
        if ip_range:
            devices = self.scan(ip_range)
            for device in devices:
                self.listbox.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}")

if __name__ == "__main__":
    app = NetworkVisualizerApp()
    app.mainloop()
