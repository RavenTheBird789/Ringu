# Ringu
Ring device detection tool — v1.2.0

Requirements:
* Ensure that the latest version of python is installed in your terminal (python 3.9+)
* `scapy` for Wi-Fi scanning (can be installed from requirements.txt)
* A wireless adapter that supports monitor mode for Wi-Fi scanning, already switched into monitor mode (ex: `sudo airmon-ng start wlan0`)
* `iw` installed (used for channel detection and hopping — ships by default on Kali)
* Root privileges for Wi-Fi packet capture
* A Linux OS or VM (the current version of Ringu isn't supported on Windows or macOS)

Installation & setup

````bash
git clone https://github.com/RavenTheBird789/Ringu
cd Ringu
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
````

To run

````bash
sudo python3 ringu.py --wifi-iface <your_interface_name>
````

Options

````bash
-h, --help         Show this help message and exit
-d, --duration     Scan time in seconds (default: 30)
--wifi-iface       Wi-Fi interface already in monitor mode (ex: wlan0mon) (required)
-o, --output       Export results to a CSV file
--no-hop           Disable channel hopping and stay on the adapter's current channel
--hop-interval     Seconds spent on each channel while hopping (default: 0.5)
--channels         Comma-separated list of channels to hop (ex: 1,6,11). Overrides auto-detection
````

Example:

````bash
# 20 second scan with CSV export
sudo python3 ringu.py --wifi-iface wlan0mon -d 20 -o scan.csv

# Scan using only specific channels instead of auto-detected ones
sudo python3 ringu.py --wifi-iface wlan0mon --channels 1,6,11 -d 20

# Scan without channel hopping (stays on whatever channel the adapter is currently set to)
sudo python3 ringu.py --wifi-iface wlan0mon --no-hop -d 20
````

How detection works:

Ringu checks for Ring devices in two ways:
* **AP mode** — catches a Ring device while it's broadcasting its own network, which typically only happens briefly during initial setup/pairing (e.g. an SSID like `Ring-XXXXXX`)
* **Connected client mode** — catches a Ring device already joined to a home Wi-Fi network, by passively reading its MAC address out of the (unencrypted) 802.11 header of data frames it sends/receives. This works even under WPA2, since Wi-Fi encryption only covers the frame payload, not the MAC header

Both methods match against a hardcoded list of known Ring MAC OUIs (manufacturer prefixes). A device is flagged if either its MAC OUI matches the list, or (AP mode only) its broadcast SSID contains "Ring".

By default, Ringu channel-hops across every channel your adapter supports, auto-detected via `iw` at startup. This is to compensate for the fact that a WiFi scan on a single fixed channel will miss any device broadcasting on a different one, regardless of distance or signal strength.

Notes:
* You must pass `--wifi-iface` for Ringu to run
* The interface must already be in monitor mode, the script does not switch it for you
* The Wi-Fi scan is passive and never transmits
* Ringu auto-detects which channels your adapter supports via `iw` and hops across all of them by default. If auto-detection fails, it falls back to channels 1, 6, and 11 (the standard non-overlapping 2.4GHz channels) and prints a warning
* Use `--channels` to manually restrict scanning to specific channels (useful if you already know the target's channel) or `--no-hop` to disable hopping entirely and stay fixed on the adapter's current channel
* Channel hopping improves coverage but trades off continuous listening time on any single channel — faster `--hop-interval` values cover more ground per sweep but spend less time per channel, and vice versa
* The OUI list is a fixed, manually curated set and may not cover every Ring hardware generation or manufacturer range — a non-match doesn't guarantee a device isn't a Ring product
* Devices using MAC address randomization will not match OUI-based detection, regardless of scan conditions
* Client-mode detection depends on the device actively transmitting (e.g. motion-triggered recording, live view, periodic heartbeat traffic) during the scan window — an idle device may not generate traffic to detect
* Detection is substantially less reliable from a moving vehicle than standing still, due to shorter dwell time and lower chances of channel/timing alignment
* KeyboardInterrupt (Ctrl + C) can be used to stop the scan early, the summary will still print and the CSV will still export with whatever was found
* CSV columns are `mac_addr, ssid, rssi, channel, source` (`source` indicates whether the match came from `beacon/probe-resp` or `data-frame`; `ssid` and `channel` are only populated for AP-mode matches)
* If no duration is provided, the default is 30 seconds

Updates:

**v1.2.0**
* Added automatic channel detection via `iw`, so Ringu only hops channels the connected adapter actually supports instead of relying on a fixed hardcoded list
* Added channel hopping during scans, cycling through supported channels in a background thread while capture continues uninterrupted — previously Ringu only listened on whatever single channel the adapter happened to be set to
* Added `--channels` to manually specify an exact channel list, overriding auto-detection
* Added `--hop-interval` to control how long the adapter dwells on each channel before hopping
* Added `--no-hop` to disable hopping and preserve the old single-channel behavior
* Added a fallback channel list (`1, 6, 11`) used if auto-detection via `iw` fails for any reason
* Fixed a bug in `is_ring_mac()` where OUI matching was case-sensitive and compared against uppercase values, while `scapy` returns MAC addresses in lowercase — this meant OUI-based detection could silently fail to match valid Ring devices
* Changed OUI matching from a substring check (`in`) to a prefix check (`startswith`), so a MAC is only flagged when the OUI genuinely matches its first three bytes, rather than matching anywhere in the address
