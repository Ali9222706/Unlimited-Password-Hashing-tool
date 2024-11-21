import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import threading

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")

        # Create a text area to display captured packets
        self.text_area = scrolledtext.ScrolledText(master, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)

        # Create a start button
        self.start_button = tk.Button(master, text="Start Capturing", command=self.start_capturing)
        self.start_button.pack(pady=5)

        # Create a stop button
        self.stop_button = tk.Button(master, text="Stop Capturing", command=self.stop_capturing)
        self.stop_button.pack(pady=5)

        self.sniffer_thread = None
        self.is_sniffing = False

    def start_capturing(self):
        self.is_sniffing = True
        self.text_area.delete(1.0, tk.END)  # Clear previous output
        self.text_area.insert(tk.END, "Starting packet capture...\n")
        
        # Start the sniffer in a new thread
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.start()

    def stop_capturing(self):
        self.is_sniffing = False
        self.text_area.insert(tk.END, "Stopping packet capture...\n")

    def sniff_packets(self):
        # This function runs in a separate thread
        sniff(prn=self.packet_callback, store=0)

    def packet_callback(self, packet):
        # Check if capturing is still active
        if not self.is_sniffing:
            return
        
        # Format the packet summary and display it in the text area
        self.text_area.insert(tk.END, str(packet.summary()) + "\n")
        self.text_area.see(tk.END)  # Scroll to the end

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()