# Ringu
Ring device detection tool

Requirements:
* Ensure that the latest version of python is installed in your terminal (python 3.9+)
* `scapy` for Wi-Fi scanning (can be installed from requirements.txt)
* A wireless adapter that supports monitor mode for Wi-Fi scanning already switched into monitor mode (ex: `sudo airmon-ng start wlan0`)
* Root privileges for Wi-Fi packet capture
* A Linux OS or VM (The current version of Ringu isn't supported Windows or MacOS)

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
````

Example:

````bash
# 20 second scan with CSV export
sudo python3 ringu.py --wifi-iface wlan0mon -d 20 -o scan.csv
````

Notes:
* You must pass `--wifi-iface` for Ringu to run
* The interface must already be in monitor mode, the script does not switch it for you
* The Wi-Fi scan is passive and never transmits
* KeyboardInterrupt (Ctrl + C) can be used to stop the scan early, the summary will still print and the CSV will still export with whatever was found
* CSV columns are `mac_addr, ssid, rssi, channel`
* If no duration is provided, the default is 30 seconds


