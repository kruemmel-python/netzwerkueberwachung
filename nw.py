import psutil
import socket
import time
import geoip2.database
from scapy.all import sniff, IP
import tkinter as tk
from tkinter import ttk, scrolledtext
from threading import Thread
import webbrowser
from tkinter import PhotoImage
import csv
import matplotlib.pyplot as plt
from collections import Counter
import os
import requests

# Initialisiere GeoIP2 mit der Datenbank im aktuellen Verzeichnis
try:
    geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception as e:
    print(f"Error initializing GeoIP reader: {e}")
    geoip_reader = None

# Globale Listen für pausierte und getrennte Verbindungen
paused_connections = []
disconnected_connections = []

def get_ip_data(ip):
    """
    Ruft die IP-Daten von ipinfo.io ab.

    Parameter:
    ip (str): Die IP-Adresse, für die die Daten abgerufen werden sollen.

    Rückgabe:
    dict: Ein Wörterbuch mit den IP-Daten oder einer Fehlermeldung.
    """
    url = f"https://ipinfo.io/{ip}/json"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": "Fehler beim Abrufen der IP-Daten"}

def show_ip_data(ip):
    """
    Zeigt die IP-Daten in einem neuen Fenster an.

    Parameter:
    ip (str): Die IP-Adresse, für die die Daten angezeigt werden sollen.
    """
    data = get_ip_data(ip)
    
    window = tk.Toplevel(root)
    window.title(f"IP-Daten für {ip}")
    
    text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=60, height=20)
    text_area.pack(expand=True, fill='both')
    
    if "error" in data:
        text_area.insert(tk.END, data["error"])
    else:
        for key, value in data.items():
            text_area.insert(tk.END, f"{key}: {value}\n")

def packet_callback(packet):
    """
    Callback-Funktion zur Verarbeitung von Netzwerkpaketen.

    Parameter:
    packet: Das Netzwerkpaket, das verarbeitet werden soll.
    """
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        data_size = len(packet)
        return f"IP Source: {ip_src} -> IP Destination: {ip_dst}, Size: {data_size} bytes"
    return None

def monitor_traffic(tree):
    """
    Überwacht den Netzwerkverkehr und aktualisiert die Baumansicht.

    Parameter:
    tree: Die Baumansicht, die aktualisiert werden soll.
    """
    sniff(prn=lambda x: update_tree(tree, packet_callback(x)), store=False, timeout=1)

def show_connections(tree, filter_process=None):
    """
    Zeigt die aktiven Verbindungen in der Baumansicht an.

    Parameter:
    tree: Die Baumansicht, die aktualisiert werden soll.
    filter_process (str): Optionaler Prozessname zum Filtern der Verbindungen.
    """
    tree.delete(*tree.get_children())
    for conn in psutil.net_connections():
        if conn.laddr and conn.raddr:
            local_ip, local_port = conn.laddr
            remote_ip, remote_port = conn.raddr
            process = psutil.Process(conn.pid) if conn.pid else None
            process_name = process.name() if process else "Unknown"
            if not filter_process or filter_process.lower() in process_name.lower():
                tree.insert('', 'end', values=(local_ip, local_port, remote_ip, remote_port, process_name, "active"), image=green_dot)

def show_paused_connections(tree):
    """
    Zeigt die pausierten Verbindungen in der Baumansicht an.

    Parameter:
    tree: Die Baumansicht, die aktualisiert werden soll.
    """
    tree.delete(*tree.get_children())
    for conn in paused_connections:
        tree.insert('', 'end', values=conn, image=red_dot)

def show_disconnected_connections(tree):
    """
    Zeigt die getrennten Verbindungen in der Baumansicht an.

    Parameter:
    tree: Die Baumansicht, die aktualisiert werden soll.
    """
    tree.delete(*tree.get_children())
    for conn in disconnected_connections:
        tree.insert('', 'end', values=conn)

def update_tree(tree, message):
    """
    Aktualisiert die Baumansicht mit neuen Netzwerkpaketinformationen.

    Parameter:
    tree: Die Baumansicht, die aktualisiert werden soll.
    message (str): Die Nachricht, die die Paketinformationen enthält.
    """
    if message:
        ip_src = message.split(" -> ")[0].split(": ")[1]
        ip_dst = message.split(" -> ")[1].split(",")[0].split(": ")[1]
        size = message.split(",")[1].split(": ")[1]
        location_src = get_location(ip_src)
        location_dst = get_location(ip_dst)
        tree.insert('', 'end', values=(ip_src, ip_dst, size, location_src, location_dst))

def get_location(ip):
    """
    Holt die geografische Position einer IP-Adresse.

    Parameter:
    ip (str): Die IP-Adresse, für die die Position ermittelt werden soll.

    Rückgabe:
    str: Die Position der IP-Adresse.
    """
    if geoip_reader:
        try:
            response = geoip_reader.city(ip)
            city = response.city.name or "Unknown"
            country = response.country.name or "Unknown"
            return f"{city}, {country}"
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            print(f"Error getting location for IP {ip}: {e}")
            return "Unknown"
    return "GeoIP reader not initialized"

def on_double_click(event, tree, column_index):
    """
    Event-Handler für Doppelklicks auf Baumansichtselemente.

    Parameter:
    event: Das Ereignis, das den Doppelklick beschreibt.
    tree: Die Baumansicht, auf die geklickt wurde.
    column_index (int): Der Index der Spalte, die die IP-Adresse enthält.
    """
    selected_items = tree.selection()
    if selected_items:
        item = selected_items[0]
        ip = tree.item(item, "values")[column_index]
        show_ip_data(ip)

def block_connection(ip, port):
    """
    Blockiert eine Verbindung über die Windows-Firewall.

    Parameter:
    ip (str): Die IP-Adresse, die blockiert werden soll.
    port (int): Der Port, der blockiert werden soll.
    """
    command = f"netsh advfirewall firewall add rule name=\"Block {ip}:{port}\" dir=in action=block protocol=TCP remoteip={ip} remoteport={port}"
    os.system(command)
    command = f"netsh advfirewall firewall add rule name=\"Block {ip}:{port}\" dir=out action=block protocol=TCP remoteip={ip} remoteport={port}"
    os.system(command)
    print(f"Blocked connection to {ip}:{port}")

def unblock_connection(ip, port):
    """
    Hebt die Blockierung einer Verbindung über die Windows-Firewall auf.

    Parameter:
    ip (str): Die IP-Adresse, die freigegeben werden soll.
    port (int): Der Port, der freigegeben werden soll.
    """
    command = f"netsh advfirewall firewall delete rule name=\"Block {ip}:{port}\""
    os.system(command)
    print(f"Unblocked connection to {ip}:{port}")

def pause_connection(local_ip, local_port, remote_ip, remote_port, process_name):
    """
    Pausiert eine Verbindung und fügt sie zur Liste der pausierten Verbindungen hinzu.

    Parameter:
    local_ip (str): Die lokale IP-Adresse.
    local_port (int): Der lokale Port.
    remote_ip (str): Die Remote-IP-Adresse.
    remote_port (int): Der Remote-Port.
    process_name (str): Der Name des Prozesses.
    """
    block_connection(remote_ip, remote_port)
    paused_connections.append((local_ip, local_port, remote_ip, remote_port, process_name, "paused"))
    refresh_connections(tree1)
    show_paused_connections(tree3)

def resume_connection(local_ip, local_port, remote_ip, remote_port):
    """
    Setzt eine pausierte Verbindung fort und entfernt sie aus der Liste der pausierten Verbindungen.

    Parameter:
    local_ip (str): Die lokale IP-Adresse.
    local_port (int): Der lokale Port.
    remote_ip (str): Die Remote-IP-Adresse.
    remote_port (int): Der Remote-Port.
    """
    unblock_connection(remote_ip, remote_port)
    for conn in paused_connections:
        if conn[0] == local_ip and conn[1] == local_port and conn[2] == remote_ip and conn[3] == remote_port:
            paused_connections.remove(conn)
            break
    refresh_connections(tree1)
    show_paused_connections(tree3)

def disconnect_connection(local_ip, local_port, remote_ip, remote_port, process_name):
    """
    Trennt eine Verbindung und fügt sie zur Liste der getrennten Verbindungen hinzu.

    Parameter:
    local_ip (str): Die lokale IP-Adresse.
    local_port (int): Der lokale Port.
    remote_ip (str): Die Remote-IP-Adresse.
    remote_port (int): Der Remote-Port.
    process_name (str): Der Name des Prozesses.
    """
    block_connection(remote_ip, remote_port)
    disconnected_connections.append((local_ip, local_port, remote_ip, remote_port, process_name, "disconnected"))
    refresh_connections(tree1)
    show_disconnected_connections(tree4)

def reconnect_connection(local_ip, local_port, remote_ip, remote_port):
    """
    Stellt eine getrennte Verbindung wieder her und entfernt sie aus der Liste der getrennten Verbindungen.

    Parameter:
    local_ip (str): Die lokale IP-Adresse.
    local_port (int): Der lokale Port.
    remote_ip (str): Die Remote-IP-Adresse.
    remote_port (int): Der Remote-Port.
    """
    unblock_connection(remote_ip, remote_port)
    for conn in disconnected_connections:
        if conn[0] == local_ip and conn[1] == local_port and conn[2] == remote_ip and conn[3] == remote_port:
            disconnected_connections.remove(conn)
            break
    refresh_connections(tree1)
    show_disconnected_connections(tree4)

def refresh_connections(tree, filter_process=None):
    """
    Aktualisiert die Anzeige der aktiven Verbindungen.

    Parameter:
    tree: Die Baumansicht, die aktualisiert werden soll.
    filter_process (str): Optionaler Prozessname zum Filtern der Verbindungen.
    """
    show_connections(tree, filter_process)

def refresh_traffic(tree):
    """
    Aktualisiert die Anzeige des Netzwerkverkehrs.

    Parameter:
    tree: Die Baumansicht, die aktualisiert werden soll.
    """
    tree.delete(*tree.get_children())
    monitor_traffic(tree)

def on_right_click(event, tree):
    """
    Event-Handler für Rechtsklicks auf Baumansichtselemente.

    Parameter:
    event: Das Ereignis, das den Rechtsklick beschreibt.
    tree: Die Baumansicht, auf die geklickt wurde.
    """
    iid = tree.identify_row(event.y)
    if iid:
        tree.selection_set(iid)
        menu = tk.Menu(tree, tearoff=0)
        if tree == tree1:
            menu.add_command(label="Verbindung pausieren", command=lambda: pause_selected_connection(iid))
            menu.add_command(label="Verbindung trennen", command=lambda: disconnect_selected_connection(iid))
        elif tree == tree3:
            menu.add_command(label="Verbindung fortsetzen", command=lambda: resume_selected_connection(iid))
        elif tree == tree4:
            menu.add_command(label="Verbindung wiederherstellen", command=lambda: reconnect_selected_connection(iid))
        menu.add_command(label="IP-Daten anzeigen", command=lambda: show_selected_ip_data(tree, iid))
        menu.add_command(label="Aktualisieren", command=lambda: refresh_connections(tree))
        menu.post(event.x_root, event.y_root)

def pause_selected_connection(iid):
    """
    Pausiert die ausgewählte Verbindung.

    Parameter:
    iid: Die ID des ausgewählten Elements in der Baumansicht.
    """
    if iid:
        item = tree1.item(iid, "values")
        local_ip, local_port, remote_ip, remote_port, process_name = item[0], item[1], item[2], item[3], item[4]
        pause_connection(local_ip, local_port, remote_ip, remote_port, process_name)

def resume_selected_connection(iid):
    """
    Setzt die ausgewählte pausierte Verbindung fort.

    Parameter:
    iid: Die ID des ausgewählten Elements in der Baumansicht.
    """
    if iid:
        item = tree3.item(iid, "values")
        local_ip, local_port, remote_ip, remote_port = item[0], item[1], item[2], item[3]
        resume_connection(local_ip, local_port, remote_ip, remote_port)

def disconnect_selected_connection(iid):
    """
    Trennt die ausgewählte Verbindung.

    Parameter:
    iid: Die ID des ausgewählten Elements in der Baumansicht.
    """
    if iid:
        item = tree1.item(iid, "values")
        local_ip, local_port, remote_ip, remote_port, process_name = item[0], item[1], item[2], item[3], item[4]
        disconnect_connection(local_ip, local_port, remote_ip, remote_port, process_name)

def reconnect_selected_connection(iid):
    """
    Stellt die ausgewählte getrennte Verbindung wieder her.

    Parameter:
    iid: Die ID des ausgewählten Elements in der Baumansicht.
    """
    if iid:
        item = tree4.item(iid, "values")
        local_ip, local_port, remote_ip, remote_port = item[0], item[1], item[2], item[3]
        reconnect_connection(local_ip, local_port, remote_ip, remote_port)

def show_selected_ip_data(tree, iid):
    """
    Zeigt die IP-Daten der ausgewählten Verbindung an.

    Parameter:
    tree: Die Baumansicht, aus der die Verbindung ausgewählt wurde.
    iid: Die ID des ausgewählten Elements in der Baumansicht.
    """
    if iid:
        item = tree.item(iid, "values")
        ip = item[2]  # Nehmen wir an, dass die IP-Adresse an der dritten Stelle steht
        show_ip_data(ip)

def create_filter_frame(parent):
    """
    Erstellt den Filterrahmen.

    Parameter:
    parent: Das übergeordnete Widget.
    """
    filter_frame = ttk.LabelFrame(parent, text="Filter")
    filter_frame.pack(fill="x", padx=10, pady=10)
    
    ttk.Label(filter_frame, text="Prozessname:").grid(row=0, column=0, padx=5, pady=5)
    process_name_entry = ttk.Entry(filter_frame)
    process_name_entry.grid(row=0, column=1, padx=5, pady=5)
    
    filter_button = ttk.Button(filter_frame, text="Filtern", command=lambda: filter_connections(tree1, process_name_entry.get()))
    filter_button.grid(row=0, column=2, padx=5, pady=5)

def filter_connections(tree, process_name):
    """
    Filtert die Verbindungen nach dem angegebenen Prozessnamen.

    Parameter:
    tree: Die Baumansicht, die gefiltert werden soll.
    process_name (str): Der Prozessname zum Filtern der Verbindungen.
    """
    refresh_connections(tree, process_name)

def export_connections(tree):
    """
    Exportiert die Verbindungen in eine CSV-Datei.

    Parameter:
    tree: Die Baumansicht, deren Verbindungen exportiert werden sollen.
    """
    try:
        with open('connections.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Local IP", "Local Port", "Remote IP", "Remote Port", "Process", "Status"])
            for row_id in tree.get_children():
                row = tree.item(row_id)['values']
                writer.writerow(row)
        print("Verbindungen exportiert zu connections.csv")
    except Exception as e:
        print(f"Error exporting connections: {e}")

def show_statistics(tree):
    """
    Zeigt Statistiken der Verbindungen an.

    Parameter:
    tree: Die Baumansicht, deren Verbindungen statistisch ausgewertet werden sollen.
    """
    processes = [tree.item(item)['values'][4] for item in tree.get_children()]
    counter = Counter(processes)
    labels, values = zip(*counter.items())
    
    plt.figure(figsize=(10, 5))
    plt.bar(labels, values)
    plt.xlabel('Process Name')
    plt.ylabel('Number of Connections')
    plt.title('Number of Connections per Process')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

def sort_column(tree, col, reverse):
    """
    Sortiert die Spalten der Baumansicht.

    Parameter:
    tree: Die Baumansicht, deren Spalten sortiert werden sollen.
    col (str): Die Spalte, die sortiert werden soll.
    reverse (bool): Sortierreihenfolge (aufsteigend/absteigend).
    """
    l = [(tree.set(k, col), k) for k in tree.get_children('')]
    l.sort(reverse=reverse)

    for index, (val, k) in enumerate(l):
        tree.move(k, '', index)

    tree.heading(col, command=lambda: sort_column(tree, col, not reverse))

def create_menu(root, tree1, tree2, tree3, tree4):
    """
    Erstellt das Menü der Anwendung.

    Parameter:
    root: Das Hauptfenster der Anwendung.
    tree1: Die Baumansicht der aktiven Verbindungen.
    tree2: Die Baumansicht des Netzwerkverkehrs.
    tree3: Die Baumansicht der pausierten Verbindungen.
    tree4: Die Baumansicht der getrennten Verbindungen.
    """
    menubar = tk.Menu(root)
    root.config(menu=menubar)

    options_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Optionen", menu=options_menu)
    options_menu.add_command(label="Verbindungen aktualisieren", command=lambda: refresh_connections(tree1))
    options_menu.add_command(label="Netzwerkverkehr aktualisieren", command=lambda: refresh_traffic(tree2))
    options_menu.add_command(label="Verbindungen exportieren", command=lambda: export_connections(tree1))
    options_menu.add_command(label="Statistiken anzeigen", command=lambda: show_statistics(tree1))
    options_menu.add_command(label="Pausierte Verbindungen aktualisieren", command=lambda: show_paused_connections(tree3))
    options_menu.add_command(label="Getrennte Verbindungen aktualisieren", command=lambda: show_disconnected_connections(tree4))

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Netzwerküberwachung")

    tab_control = ttk.Notebook(root)
    tab1 = ttk.Frame(tab_control)
    tab2 = ttk.Frame(tab_control)
    tab3 = ttk.Frame(tab_control)
    tab4 = ttk.Frame(tab_control)

    tab_control.add(tab1, text="Aktive Verbindungen")
    tab_control.add(tab2, text="Netzwerkverkehr")
    tab_control.add(tab3, text="Pausierte Verbindungen")
    tab_control.add(tab4, text="Getrennte Verbindungen")
    tab_control.pack(expand=1, fill='both')

    # Icons für Status
    green_dot = PhotoImage(file="green_dot.png")
    red_dot = PhotoImage(file="red_dot.png")

    # Filter Frame erstellen
    create_filter_frame(root)

    # Tabelle für aktive Verbindungen
    columns = ("Local IP", "Local Port", "Remote IP", "Remote Port", "Process", "Status")
    tree1 = ttk.Treeview(tab1, columns=columns, show='headings', selectmode='browse')
    for col in columns:
        tree1.heading(col, text=col, command=lambda _col=col: sort_column(tree1, _col, False))
        tree1.column(col, width=100)
    tree1.pack(expand=True, fill='both')

    # Rechtsklick-Ereignis binden
    tree1.bind("<Button-3>", lambda event: on_right_click(event, tree1))
    tree1.bind("<Double-1>", lambda event: on_double_click(event, tree1, 2))  # Remote IP steht an der dritten Stelle (Index 2)

    # Tabelle für Netzwerkverkehr
    columns_traffic = ("IP Source", "IP Destination", "Size", "Source Location", "Destination Location")
    tree2 = ttk.Treeview(tab2, columns=columns_traffic, show='headings', selectmode='browse')
    for col in columns_traffic:
        tree2.heading(col, text=col, command=lambda _col=col: sort_column(tree2, _col, False))
        tree2.column(col, width=100)
    tree2.pack(expand=True, fill='both')

    # Tabelle für pausierte Verbindungen
    tree3 = ttk.Treeview(tab3, columns=columns, show='headings', selectmode='browse')
    for col in columns:
        tree3.heading(col, text=col, command=lambda _col=col: sort_column(tree3, _col, False))
        tree3.column(col, width=100)
    tree3.pack(expand=True, fill='both')

    # Tabelle für getrennte Verbindungen
    tree4 = ttk.Treeview(tab4, columns=columns, show='headings', selectmode='browse')
    for col in columns:
        tree4.heading(col, text=col, command=lambda _col=col: sort_column(tree4, _col, False))
        tree4.column(col, width=100)
    tree4.pack(expand=True, fill='both')

    # Rechtsklick-Ereignis binden für pausierte Verbindungen
    tree3.bind("<Button-3>", lambda event: on_right_click(event, tree3))

    # Rechtsklick-Ereignis binden für getrennte Verbindungen
    tree4.bind("<Button-3>", lambda event: on_right_click(event, tree4))

    # Doppelklick-Ereignis binden für Netzwerkverkehr
    tree2.bind("<Double-1>", lambda event: on_double_click(event, tree2, 1))  # IP Destination steht an der zweiten Stelle (Index 1)

    # Menü erstellen
    create_menu(root, tree1, tree2, tree3, tree4)

    # Initiale Aktualisierung der Verbindungen
    refresh_connections(tree1)
    refresh_traffic(tree2)
    show_paused_connections(tree3)
    show_disconnected_connections(tree4)

    root.mainloop()
