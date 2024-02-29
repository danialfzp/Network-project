import time
import tkinter as tk
from tkinter import filedialog, ttk
from scapy.all import rdpcap
import dpkt
from geopy.geocoders import Nominatim
import folium
import socket
import concurrent.futures
import requests
import webbrowser

class PcapngAnalyzer:
    def __init__(self, master):
        self.master = master
        self.master.title("PCAPNG Analyzer")

        self.create_widgets()

    def create_widgets(self):

        self.file_path_label = tk.Label(self.master, text="Select PCAPNG file:")
        self.file_path_label.pack()

        self.file_path_entry = tk.Entry(self.master, width=50)
        self.file_path_entry.pack()

        self.browse_button = tk.Button(self.master, text="Browse", command=self.browse_file)
        self.browse_button.pack()
        
        self.protocol_var = tk.StringVar(self.master)
        self.protocol_var.set("All")  # Default selection
        self.protocol_label = tk.Label(self.master, text="Select Protocol:")
        self.protocol_label.pack()
        self.protocol_menu = tk.OptionMenu(self.master, self.protocol_var, "All", "IPv4", "IPv6", "TCP", "UDP")
        self.protocol_menu.pack()

        self.analyze_button = tk.Button(self.master, text="Analyze", command=self.analyze_pcapng)
        self.analyze_button.pack()

        self.geolocate_button = tk.Button(self.master, text="Geolocate IPs", command=self.geolocate_ips)
        self.geolocate_button.pack()

        self.sort_button = tk.Button(self.master, text="Sort Packets", command=self.sort_packets)
        self.sort_button.pack()

        self.result_text = tk.Text(self.master, height=10, width=50, wrap=tk.NONE)
        self.result_text.pack(side=tk.LEFT, fill=tk.Y)
        self.result_scrollbar = tk.Scrollbar(self.master, command=self.result_text.yview)
        self.result_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text['yscrollcommand'] = self.result_scrollbar.set

        self.tree = ttk.Treeview(self.master, columns=("Time", "Source", "Destination", "Protocol"), show="headings")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.pack()

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap"), ("PCAPNG Files", "*.pcapng")])
        self.file_path_entry.delete(0, tk.END)
        self.file_path_entry.insert(0, file_path)

    def analyze_pcapng(self):
        file_path = self.file_path_entry.get()
        if not file_path:
            self.display_result("Please select a PCAP or PCAPNG file.")
            return

        try:
            protocol_counts = self.count_protocols(file_path)

            self.display_result("Protocols and their occurrences:\n")
            for protocol, count in protocol_counts.items():
                self.display_add_result(f"{protocol}: {count}\n")

        except Exception as e:
            self.display_result(f"Error analyzing PCAPNG file: {str(e)}")

    def count_protocols(self, pcap_file):
        packets = rdpcap(pcap_file)

        protocol_counts = {}
        for packet in packets:
            for layer in packet.layers():
                if layer not in protocol_counts:
                    protocol_counts[layer] = 1
                else:
                    protocol_counts[layer] += 1

        return protocol_counts

    def geolocate_ips(self):
        file_path = self.file_path_entry.get()
        if not file_path:
            self.display_result("Please select a PCAP or PCAPNG file.")
            return

        try:
            ips = self.extract_ips_from_pcapng(file_path)
            geolocator = Nominatim(user_agent="ip_locator")
            locations = {}

            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_ip = {executor.submit(self.get_location, ip, geolocator): ip for ip in ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        location = future.result()
                        isp = self.get_isp_info(ip)
                        locations[ip] = {"location": location, "isp": isp}
                    except Exception as e:
                        print(f"Error processing IP {ip}: {e}")

            self.display_result("IPs Geolocated. Generating Map...\n")
            time.sleep(1)

            self.plot_on_map(locations)
            self.display_result("Map generated. Opening in browser...\n")
            webbrowser.open("ip_locations_map.html")

        except Exception as e:
            self.display_result(f"Error geolocating IPs: {str(e)}")

    def extract_ips_from_pcapng(self, file_path):
        ips = set()
        with open(file_path, 'rb') as file:
            pcap = dpkt.pcapng.Reader(file)
            for ts, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    ips.add(socket.inet_ntoa(ip.src))
                    ips.add(socket.inet_ntoa(ip.dst))
        return list(ips)

    def get_location(self, ip, geolocator):
        try:
            location = geolocator.geocode(ip, timeout=10.0)
            return (location.latitude, location.longitude) if location else None
        except Exception as e:
            print(f"Error geocoding IP {ip}: {e}")
            return None

    def get_isp_info(self, ip):
        try:
            response = requests.get(f"http://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                data = response.json()
                return data.get("org", "Unknown ISP")
            else:
                return "Unknown ISP"
        except Exception as e:
            print(f"Error retrieving ISP information for IP {ip}: {e}")
            return "Unknown ISP"

    def sort_packets(self):
        file_path = self.file_path_entry.get()
        if not file_path:
            self.display_result("Please select a PCAP or PCAPNG file.")
            return

        protocol_filter = self.protocol_var.get()
        try:
            packets = rdpcap(file_path)

            if protocol_filter == "All":
                filtered_packets = packets
            else:
                filtered_packets = [packet for packet in packets if self.packet_matches_protocol(packet, protocol_filter)]

            self.display_result("Showing sorted packets in a table:\n")
            self.display_table(filtered_packets)

        except Exception as e:
            self.display_result(f"Error sorting packets: {str(e)}")

    def packet_matches_protocol(self, packet, protocol):
        if protocol == "IPv4" and packet.haslayer('IP'):
            return True
        elif protocol == "IPv6" and packet.haslayer('IPv6'):
            return True
        elif protocol == "TCP" and packet.haslayer('TCP'):
            return True
        elif protocol == "UDP" and packet.haslayer('UDP'):
            return True
        else:
            return False

    def display_table(self, packets):
        for packet in packets:
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(packet.time))
            source = packet[0][1].src
            destination = packet[0][1].dst
            protocol = packet.name

            self.tree.insert("", "end", values=(time_str, source, destination, protocol))

    def plot_on_map(self, locations):
        m = folium.Map(location=[0, 0], zoom_start=2)
        for ip, loc_info in locations.items():
            location = loc_info["location"]
            isp = loc_info["isp"]
            if location:
                popup_content = f"IP: {ip}<br>Location: {location}<br>ISP: {isp}"
                folium.Marker(location=location, popup=popup_content).add_to(m)
        m.save("ip_locations_map.html")

    def display_result(self, message):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, message)
        self.result_text.config(state=tk.DISABLED)

    def display_add_result(self, message):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.insert(tk.END, message)
        self.result_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = PcapngAnalyzer(root)
    root.mainloop()
