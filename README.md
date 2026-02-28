# DOSDETECTOR
---
## Introduction
- This project has been created to dectect Dos (Denial of services) attacks for Windows and Linux devices. The core component of this code relies on [pcap library](https://www.tcpdump.org/manpages/pcap.3pcap.html).
---
## Main idea
- Using pcap library to capture packets on the socket, then measuring time per DOSTIMETHRESHOLD to determine attack threshold.
In this project, I tried to simulate a Dos attack and measured that 8000 packets (DOSPACKETTHRESHOLD) per 10 seconds (DOSTIMETHRESHOLD) is a reasonable numbers.
---
## Installation
### HTTPS Clone
- Open the Powershell/Terminal and typing:
```bash 
# Clone DosDetector repository
clone https://github.com/khainguyendiep/DosDetector
# Navigate to the cloned directory
cd DosDetector
```

### For Windows
- Currently, it is not supported for Windows.

### For Linux
- Install g++:
```bash
sudo apt install build-essential gdb
```
- Install pcap library:
```bash
sudo apt install libpcap-dev
```
- Open the terminal and move to folder has been cloned and typing on the terminal:
```bash
# Compile the code
exec "!g++ -std=c++17 -Wall % -o %< -lpcap && sudo ./%<"
```
### Running
- Running the executed file that was just created.
- Choosing an network card you want to use.
- Waiting for Dos attack, and enjoy.
---
## Acknowledgements
- [uthash.h](https://github.com/troydhanson/uthash/blob/2031adfd8cd6f8f498e0f4a9055648b19496f12e/src/uthash.h) - A library for creating and managing hash tables for character arrays, developed by [Troy D. Hanson](https://github.com/troydhanson) and community.
---
## License
- This project is licensed under the **MIT License** - see the [LICENSE](https://github.com/khainguyendiep/DosDetector/blob/main/LICENSE) file for details.
### Third-party Licenses
- This project incorporates code from [Troy D. Hanson](https://github.com/troydhanson) licensed under the BSD License.
