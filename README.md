# Project-code

#!/usr/bin/env python
import pandas as pd
import numpy as np
import scapy.all as scapy
import socket
from sklearn.ensemble import RandomForestClassifier
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from PIL import Image, ImageTk


# Define the mapping of ports to services
services = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP Server',
    68: 'DHCP Client',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    119: 'NNTP',
    123: 'NTP',
    135: 'RPC Endpoint Mapper',
    137: 'NetBIOS Name Service',
    138: 'NetBIOS Datagram Service',
    139: 'NetBIOS Session Service',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP Trap',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'Microsoft DS',
    465: 'SMTPS',
    587: 'SMTP (submission)',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'Microsoft SQL Server',
    1434: 'Microsoft SQL Monitor',
    3306: 'MySQL',
    3389: 'Remote Desktop Protocol',
    5432: 'PostgreSQL',
    5900: 'Virtual Network Computing (VNC)',
    8080: 'HTTP alternate'
}

# Load and preprocess the data
data = pd.read_csv('preprocessed_train_data_normalized.csv')
data['label'] = data['label'].astype(int)  # convert label column to integer
X = data.drop('label', axis=1)  # features
X.columns = range(X.shape[1])  # set feature names to integers
y = data['label']  # target variable

# Train the random forest classifier
rf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
rf.fit(X, y)

# Define function to trigger port scan and attack detection
scan_result = ""

def scan_ports():
    global scan_result
    # Get the IP address to scan from the user
    ip_address = ip_entry.get()

    # Port scan and attack detection
    open_ports = {}
    total_ports = len(services)
    progress = 0

    # Create progress bar widget with green color
    style = ttk.Style()
    style.configure("green.Horizontal.TProgressbar", background='green')
    progress_bar = ttk.Progressbar(main_tab, length=200, mode='determinate', style="green.Horizontal.TProgressbar")
    progress_bar.pack(pady=10)

    for port in services.keys():
        sock = scapy.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            service_name = services[port]
            open_ports[port] = service_name
        sock.close()

        # Update progress bar
        progress += 1
        progress_percentage = (progress / total_ports) * 100
        progress_bar['value'] = progress_percentage
        main_tab.update_idletasks()

    # Destroy progress bar widget after scan completes
    progress_bar.destroy()

    if len(open_ports) == 0:
        scan_result = f"Target IP: {ip_address}\nOpen ports: None\nNo attack detected."
    else:
        scan_result = f"Target IP: {ip_address}\nOpen ports:\n"
        for port, service in open_ports.items():
            scan_result += f"- Port {port}: {service}\n"
        # Convert port scan results to feature vector
        port_vector = np.zeros(len(X.columns))
        for port in open_ports.keys():
            if port in X.columns:
                port_vector[X.columns.get_loc(port)] = 1

        # Predict using the trained random forest classifier
        result = rf.predict([port_vector])[0]
        if result == 0:
            scan_result += "No attack detected."
        else:
            if result == 1:
                scan_result += "Attack detected."
            messagebox.showwarning("Attack Detection Result", "Attack detected.")

    scan_result_label.configure(text=scan_result)



# Create GUI window
root = tk.Tk()
root.title("SCAN SENSE")
root.geometry("600x600")
 

# Create a notebook widget
notebook = ttk.Notebook(root)
notebook.pack(fill='both', expand=True)

# Add the main tab to the notebook
main_tab = ttk.Frame(notebook)
notebook.add(main_tab, text="Scan")

# Add the "About ScanSense" tab to the notebook
about_us_tab = ttk.Frame(notebook)
notebook.add(about_us_tab, text="About ScanSense")

# Load the scan image
scan_image = Image.open("scan.png")
scan_image = scan_image.resize((250, 250), Image.LANCZOS)
scan_photo = ImageTk.PhotoImage(scan_image)


# Add the scan image to the main tab
scan_label = tk.Label(main_tab, image=scan_photo)
scan_label.pack(pady=10)

# Create a frame for the IP address label and entry field
ip_frame = tk.Frame(main_tab)
ip_frame.pack(side=tk.TOP, pady=20)


# Create label and entry field for IP address
ip_label = tk.Label(ip_frame, text="Enter the IP address to scan:")
ip_label.pack(side=tk.TOP, padx=10, pady=10)

ip_entry = tk.Entry(ip_frame)
ip_entry.pack(side=tk.TOP, padx=10, pady=10)

# Create label to display the port scan and attack detection results
scan_result_label = tk.Label(main_tab, text="")
scan_result_label.pack()

# Create the buttons and pack them side by side
scan_button = tk.Button(main_tab, text="Scan Ports", command=scan_ports)
scan_button.pack(side=tk.TOP, padx=(20, 5), pady=5)

# Define the function to display information about the program
def display_about_us():
    # Create a label with the about us text
    about_us_text = "This is the about us paragraph."
    about_us_text_label = tk.Label(about_us_tab, text=about_us_text)
    about_us_text_label.pack()

# Call the function to display the about us information
display_about_us()

# Start GUI event loop
root.mainloop()
