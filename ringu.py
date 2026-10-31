# Ringu
# Ring camera/device detection tool

import argparse
import sys
import csv
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt

def blue(text: str) -> str:
    return f"\033[94m{text}\033[0m"

def bold(text: str) -> str:
    return f"\033[1m{text}\033[0m"

def red(text: str) -> str:
    return f"\033[91m{text}\033[0m"

def green(text: str) -> str:
    return f"\033[92m{text}\033[0m"

mac_oui_list = ["54:E0:19", "00:B4:63", "18:7F:88", "24:2B:D6", "34:3E:A4", "50:E4:67", "5C:47:5E", "64:9A:63", "90:48:6C", "9C:76:13", "AC:9F:C3", "C4:DB:AD", "CC:3B:FB"]

def ring_art():
    art = ["     ▄▄▄▄▄▄▄▄▄    ",
           "   ▄█▀▀     ▀▀█▄  ",
           "  ██           ██ ",
           " ██             ██",
           " ██             ██",
           "  ██           ██ ",
           "   ▀█▄▄     ▄▄█▀  ",
           "     ▀▀▀▀▀▀▀▀▀    "]
    for line in art:
        print(blue(line))

def trademark(main):
    def wrapper():
        title = "Ringu"
        author = "By: RavenTheBird789"
        ring_art()
        print(red(f"{title:^20}"))
        print(blue("-" * 19))
        print(bold(red(f"{author:^18}")))
        print(blue("-" * 19) + "\n")
        main()
    return wrapper

def discover_wifi_devices(interface, duration=30, output=None):
    """
    Passively discover nearby WiFi devices (APs) via beacon/probe-response frames.

    Args:
        interface (str): WiFi adapter in monitor mode (e.g. 'wlan0mon')
        duration (int): how long to scan, in seconds (default 30)
    """
    found_any = False
    results = []

    def handle_packet(pkt):
        nonlocal found_any

        if not pkt.haslayer(Dot11):
            return

        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            return

        mac_addr = pkt[Dot11].addr2
        ssid = None
        channel = None
        rssi = None

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode(errors="replace")
                except Exception:
                    ssid = None
            elif elt.ID == 3:
                try:
                    channel = ord(elt.info)
                except Exception:
                    channel = None
            elt = elt.payload.getlayer(Dot11Elt)

        try:
            rssi = pkt.dBm_AntSignal
        except Exception:
            rssi = None

        for mac_oui in mac_oui_list:
            if (mac_oui in mac_addr):
                found_any = True
                print(green("Ring Device Detected!"))
                print(f"MAC: {mac_addr}  Name: {ssid}  RSSI: {rssi}  Channel: {channel}\n")
        if ("Ring" in ssid):
            found_any = True
            print(green("Ring Device Detected!"))
            print(f"MAC: {mac_addr}  Name: {ssid}  RSSI: {rssi}  Channel: {channel}\n")            
            results.append({
                "mac_addr": mac_addr,
                "ssid": ssid,
                "rssi": rssi,
                "channel": channel,
            })       
        else:
            return

    sniff(iface=interface, prn=handle_packet, timeout=duration, store=False)

    if not found_any:
        print(red(f"[!] No matching devices found within {duration} seconds."))
    elif output:
        with open(output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["mac_addr", "ssid", "rssi", "channel"])
            writer.writeheader()
            writer.writerows(results)
        print(f"[*] Exported {len(results)} devices to {output}")

@trademark
def main():
    ap = argparse.ArgumentParser(
        description="Passive WiFi scanner - discovers nearby APs via beacon/probe-response frames.",
        epilog="Example: sudo python3 ringu.py --wifi-iface wlan0mon -d 20 -o scan.csv"
    )
    ap.add_argument("-d", "--duration", type=int, default=30,
                     help="Scan duration in seconds (default: 30)")
    ap.add_argument("--wifi-iface", required=True,
                     help="WiFi interface already in monitor mode (e.g. wlan0mon)")
    ap.add_argument("-o", "--output",
                     help="Export results to a CSV file")
    args = ap.parse_args()

    if not args.wifi_iface:
        print(red("[!] --wifi-iface is required for WiFi scanning."))
        sys.exit(1)

    discover_wifi_devices(args.wifi_iface, duration=args.duration, output=args.output)

if __name__ == "__main__":
    main()