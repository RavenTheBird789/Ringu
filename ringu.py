# Ringu
# Ring camera/device detection tool

import argparse
import sys
import csv
import subprocess
import threading
import time
import re
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

# This fallback list is only used if auto-detection fails and no --channels override is given
FALLBACK_CHANNELS = [1, 6, 11]

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
        version = "1.2.0"
        ring_art()
        print(red(f"{title:^20}"))
        print(blue("-" * 19))
        print(f"{version:^19}")
        print(blue("-" * 19))
        print(bold(red(f"{author:^18}")))
        print(blue("-" * 19) + "\n")
        main()
    return wrapper

def is_ring_mac(mac_addr):
    if mac_addr is None:
        return False
    normalized = mac_addr.lower()
    return any(normalized.startswith(oui.lower()) for oui in mac_oui_list)

def detect_supported_channels(interface):
    """
    Query the adapter's actual supported channels via `iw list`.
    Returns a sorted list of channel numbers, or None if detection fails.
    """
    try:
        phy_result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True, text=True, timeout=5
        )
        phy_match = re.search(r"wiphy\s+(\d+)", phy_result.stdout)
        if not phy_match:
            return None
        phy_num = phy_match.group(1)

        iw_result = subprocess.run(
            ["iw", f"phy{phy_num}", "info"],
            capture_output=True, text=True, timeout=5
        )
        output = iw_result.stdout
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return None

    channels = []
    for line in output.splitlines():
        if "MHz" not in line or "[" not in line:
            continue
        if "disabled" in line.lower():
            continue
        match = re.search(r"\[(\d+)\]", line)
        if match:
            channels.append(int(match.group(1)))

    return sorted(set(channels)) if channels else None

def channel_hopper(interface, channels, stop_event, hop_interval=0.5):
    """
    Background thread: cycles the interface through the given channel list.
    """
    while not stop_event.is_set():
        for ch in channels:
            if stop_event.is_set():
                break
            try:
                subprocess.run(
                    ["iw", "dev", interface, "set", "channel", str(ch)],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError:
                continue
            time.sleep(hop_interval)

def discover_wifi_devices(interface, duration=30, output=None, hop=True, hop_interval=0.5, channels=None):
    """
    Passively discover nearby Ring devices via:
      1. Beacon/probe-response frames (AP-mode, e.g. Ring in setup mode)
      2. Data frame MAC headers (client-mode, e.g. Ring already on a network)

    Args:
        interface (str): WiFi adapter in monitor mode (e.g. 'wlan0mon')
        duration (int): how long to scan, in seconds (default 30)
        output (str): optional path to export results as CSV
        hop (bool): whether to channel-hop during the scan (default True)
        hop_interval (float): seconds spent on each channel before hopping
        channels (list[int] or None): explicit channel list to use; if None, auto-detect
    """
    found_any = False
    results = []
    seen_macs = set()

    if hop:
        if channels is None:
            detected = detect_supported_channels(interface)
            if detected:
                channels = detected
                print(green(f"[*] Auto-detected {len(channels)} supported channel(s): {channels}"))
            else:
                channels = FALLBACK_CHANNELS
                print(red(f"[!] Could not auto-detect supported channels — "
                           f"falling back to {channels}. Use --channels to override."))
        else:
            print(green(f"[*] Using manually specified channels: {channels}"))

    stop_event = threading.Event()
    hopper_thread = None

    if hop:
        hopper_thread = threading.Thread(
            target=channel_hopper,
            args=(interface, channels, stop_event, hop_interval),
            daemon=True
        )
        hopper_thread.start()

    def handle_ap_frame(pkt):
        nonlocal found_any

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

        if mac_addr is None:
            return

        matched = is_ring_mac(mac_addr)
        if ssid is not None and "Ring" in ssid:
            matched = True

        if matched and mac_addr not in seen_macs:
            seen_macs.add(mac_addr)
            found_any = True
            print(green("Ring Device Detected! (AP mode)"))
            print(f"MAC: {mac_addr}  Name: {ssid}  RSSI: {rssi}  Channel: {channel}\n")
            results.append({
                "mac_addr": mac_addr,
                "ssid": ssid,
                "rssi": rssi,
                "channel": channel,
                "source": "beacon/probe-resp",
            })

    def handle_data_frame(pkt):
        nonlocal found_any

        dot11 = pkt[Dot11]
        to_ds = dot11.FCfield & 0x1 != 0
        from_ds = dot11.FCfield & 0x2 != 0

        if to_ds and not from_ds:
            client_mac = dot11.addr2
        elif from_ds and not to_ds:
            client_mac = dot11.addr1
        else:
            return

        try:
            rssi = pkt.dBm_AntSignal
        except Exception:
            rssi = None

        if client_mac is None:
            return

        if is_ring_mac(client_mac) and client_mac not in seen_macs:
            seen_macs.add(client_mac)
            found_any = True
            print(green("Ring Device Detected! (connected client)"))
            print(f"MAC: {client_mac}  RSSI: {rssi}\n")
            results.append({
                "mac_addr": client_mac,
                "ssid": None,
                "rssi": rssi,
                "channel": None,
                "source": "data-frame",
            })

    def handle_packet(pkt):
        if not pkt.haslayer(Dot11):
            return

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            handle_ap_frame(pkt)
        elif pkt.type == 2:
            handle_data_frame(pkt)

    try:
        sniff(iface=interface, prn=handle_packet, timeout=duration, store=False)
    finally:
        stop_event.set()
        if hopper_thread is not None:
            hopper_thread.join(timeout=2)
    
    if not found_any:
        print(red(f"[!] No ring devices found within {duration} seconds."))
    elif output:
        with open(output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["mac_addr", "ssid", "rssi", "channel", "source"])
            writer.writeheader()
            writer.writerows(results)
        print(green(f"[*] Exported {len(results)} devices to {output}"))

@trademark
def main():
    ap = argparse.ArgumentParser(
        description="Passive WiFi scanner - discovers nearby Ring devices via AP beacons and client data frames.",
        epilog="Example: sudo python3 ringu.py --wifi-iface wlan0mon -d 20 -o scan.csv"
    )
    ap.add_argument("-d", "--duration", type=int, default=30,
                     help="Scan duration in seconds (default: 30)")
    ap.add_argument("--wifi-iface", required=True,
                     help="WiFi interface already in monitor mode (e.g. wlan0mon)")
    ap.add_argument("-o", "--output",
                     help="Export results to a CSV file")
    ap.add_argument("--no-hop", action="store_true",
                     help="Disable channel hopping and stay on the adapter's current channel")
    ap.add_argument("--hop-interval", type=float, default=0.5,
                     help="Seconds spent on each channel while hopping (default: 0.5)")
    ap.add_argument("--channels", type=str,
                     help="Comma-separated list of channels to hop (e.g. 1,6,11). "
                          "Overrides auto-detection.")
    args = ap.parse_args()

    if not args.wifi_iface:
        print(red("[!] --wifi-iface is required for WiFi scanning."))
        sys.exit(1)

    manual_channels = None
    if args.channels:
        try:
            manual_channels = [int(c.strip()) for c in args.channels.split(",")]
        except ValueError:
            print(red("[!] --channels must be a comma-separated list of integers, e.g. 1,6,11"))
            sys.exit(1)

    discover_wifi_devices(
        args.wifi_iface,
        duration=args.duration,
        output=args.output,
        hop=not args.no_hop,
        hop_interval=args.hop_interval,
        channels=manual_channels,
    )

if __name__ == "__main__":
    main()
