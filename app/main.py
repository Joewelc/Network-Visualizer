import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, Toplevel, Checkbutton, BooleanVar
from scapy.all import srp, Ether, ARP, ICMP, IP
import threading
import netifaces
import subprocess

class NetworkVisualizerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.configure(bg='#2E2E2E')
        self.title("JW's Network Visualizer")
        self.geometry("500x400")

        style = ttk.Style()
        style.theme_use('aqua')
        style.configure("Custom.Vertical.TScrollbar", background="#555555")

        self.label = ttk.Label(self, text="Network Devices:", background='#2E2E2E', foreground='#FFFFFF')
        self.label.pack()

        self.scrollbar = ttk.Scrollbar(self, orient="vertical", style="Custom.Vertical.TScrollbar")
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.listbox = tk.Listbox(self, yscrollcommand=self.scrollbar.set, bg="#2E2E2E", fg="#FFFFFF", font=("Product Sans", 18))
        self.listbox.pack(fill=tk.BOTH, expand=1)

        self.scrollbar.config(command=self.listbox.yview)

        self.scan_button = ttk.Button(self, text="Scan", command=self.open_filter_window)
        self.scan_button.pack()

        self.exit_button = ttk.Button(self, text="Exit", command=self.quit)
        self.exit_button.pack()

        self.schedule_refresh()

        # Filter variables
        self.show_ip = BooleanVar(value=True)
        self.show_mac = BooleanVar(value=True)
        self.show_status = BooleanVar(value=True)

    def is_device_online(self, ip):
        """
        Check if a device is online by sending an ICMP ping.
        """
        resp, _ = srp(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
        return bool(resp)

    def get_subnet(self):
        """
        Get the local subnet in CIDR notation.
        """
        gws = netifaces.gateways()
        default_gateway = gws.get('default')
        if default_gateway:
            default_interface = default_gateway.get(netifaces.AF_INET)[1]
            ip_info = netifaces.ifaddresses(default_interface).get(netifaces.AF_INET)[0]
            netmask = ip_info['netmask']
            cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
            subnet = f"{ip_info['addr']}/{cidr}"
            return subnet

    def scan(self, ip):
        try:
            request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(request, timeout=2, verbose=0)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            return

        for _, packet in ans:
            ip_addr = packet.psrc
            mac_addr = packet.hwsrc
            status = "Online" if self.is_device_online(ip_addr) else "Offline"
            entry = ""
            if self.show_ip.get():
                entry += f"IP: {ip_addr} "
            if self.show_mac.get():
                entry += f"MAC: {mac_addr} "
            if self.show_status.get():
                entry += f"Status: {status}"
            self.listbox.insert(tk.END, entry)

    def open_filter_window(self):
        filter_window = Toplevel(self)
        filter_window.title("Filter Options")

        ip_check = Checkbutton(filter_window, text="Show IP", variable=self.show_ip)
        ip_check.pack()

        mac_check = Checkbutton(filter_window, text="Show MAC Address", variable=self.show_mac)
        mac_check.pack()

        status_check = Checkbutton(filter_window, text="Show Online Status", variable=self.show_status)
        status_check.pack()

        scan_button = ttk.Button(filter_window, text="Start Scan",
                                 command=lambda: [self.start_scan(), filter_window.destroy()])
        scan_button.pack()

    def scan_network(self):
        """
        Populate the listbox with devices found on the network.
        """
        subnet = self.get_subnet()
        if subnet:
            self.scan(subnet)

    def start_scan(self):
        """
        Start scanning in a non-blocking manner.
        """
        threading.Thread(target=self.scan_network, daemon=True).start()

    def refresh_device_status(self):
        """
        Refresh the device status in the GUI listbox.
        """
        current_selection = self.listbox.curselection()
        self.listbox.delete(0, tk.END)
        subnet = self.get_subnet()
        if subnet:
            self.scan(subnet)

        if current_selection:
            self.listbox.select_set(current_selection[0])

        # Schedule the next refresh
        self.after(30000, self.refresh_device_status)  # 30000 milliseconds = 30 seconds

    def schedule_refresh(self):
        """
        Schedule the device status refresh.
        """
        self.after(30000, self.refresh_device_status)

    def is_device_online(self, ip):
        """
        Check if a device is online using ping.
        """
        try:
            # Use the system's ping command with count 1 and timeout 3
            subprocess.check_output(["ping", "-c", "1", "-W", "3", ip], stderr=subprocess.STDOUT)
            return True
        except subprocess.CalledProcessError:
            return False

if __name__ == "__main__":
    app = NetworkVisualizerApp()
    app.mainloop()
