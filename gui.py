import tkinter as tk
from tkinter import ttk
from threading import Thread
from sniffer import start_sniffer

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer")
        self.root.geometry("600x400")

        self.start_button = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing_thread)
        self.start_button.pack(pady=10)

        self.log_text = tk.Text(root)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def start_sniffing_thread(self):
        thread = Thread(target=start_sniffer)
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferGUI(root)
    root.mainloop()
