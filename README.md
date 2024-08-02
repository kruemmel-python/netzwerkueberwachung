# Netzwerküberwachung

Ein Netzwerküberwachungsprogramm, das aktive Verbindungen, Netzwerkverkehr und pausierte sowie getrennte Verbindungen anzeigt. Das Programm bietet Funktionen zum Pausieren, Trennen und Wiederherstellen von Verbindungen, sowie zur Anzeige von IP-Daten.

## Funktionen

- Anzeige aktiver Verbindungen mit IP-Adressen, Ports und Prozessnamen
- Überwachung des Netzwerkverkehrs
- Pausieren und Fortsetzen von Verbindungen
- Trennen und Wiederherstellen von Verbindungen
- Anzeige von IP-Daten über die IPinfo API
- Export von Verbindungen in eine CSV-Datei
- Statistische Auswertung der Verbindungen
- Sortierung der Tabellen nach Spalten

## Installation

1. Klone das Repository:
    ```bash
    git clone https://github.com/kruemmel-python/netzwerkueberwachung.git
    ```
2. Wechsle in das Projektverzeichnis:
    ```bash
    cd netzwerkueberwachung
    ```
3. Erstelle und aktiviere eine virtuelle Umgebung (optional, aber empfohlen):
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/MacOS
    venv\Scripts\activate  # Windows
    ```
4. Installiere die benötigten Pakete:
    ```bash
    pip install -r requirements.txt
    ```

## Verwendung

1. Starte das Programm:
    ```bash
    python nw.py
    ```
2. Verwende die Tabs, um zwischen aktiven Verbindungen, Netzwerkverkehr, pausierten Verbindungen und getrennten Verbindungen zu wechseln.

### Kontextmenü

- **Aktive Verbindungen**:
  - **Verbindung pausieren**: Pausiert die ausgewählte Verbindung.
  - **Verbindung trennen**: Trennt die ausgewählte Verbindung.
  - **IP-Daten anzeigen**: Zeigt Informationen zur IP-Adresse an.
  - **Aktualisieren**: Aktualisiert die Anzeige der aktiven Verbindungen.

- **Pausierte Verbindungen**:
  - **Verbindung fortsetzen**: Setzt die ausgewählte pausierte Verbindung fort.
  - **IP-Daten anzeigen**: Zeigt Informationen zur IP-Adresse an.
  - **Aktualisieren**: Aktualisiert die Anzeige der pausierten Verbindungen.

- **Getrennte Verbindungen**:
  - **Verbindung wiederherstellen**: Stellt die ausgewählte getrennte Verbindung wieder her.
  - **IP-Daten anzeigen**: Zeigt Informationen zur IP-Adresse an.
  - **Aktualisieren**: Aktualisiert die Anzeige der getrennten Verbindungen.

- **Netzwerkverkehr**:
  - **IP-Daten anzeigen**: Zeigt Informationen zur IP-Adresse an.
  - **Aktualisieren**: Aktualisiert die Anzeige des Netzwerkverkehrs.

## Anforderungen

- Python 3.x
- Abhängigkeiten (siehe `requirements.txt`)

## Abhängigkeiten

- psutil
- scapy
- tkinter
- geoip2
- requests
- matplotlib

## Lizenz

Dieses Projekt steht unter der MIT-Lizenz.

## Autor

- **Ralf Krümmel** - https://github.com/kruemmel-python


