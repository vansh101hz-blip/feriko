# Feixiao

Feixiao is a macOS kernel extension that ports the Linux `rtw88` driver, bringing support for Realtek PCIe Wi-Fi cards to macOS.

## Supported Hardware

Feixiao aims to support the following Realtek chipsets:
- RTL8822BE
- RTL8822CE
- RTL8821CE
- RTL8821AE
- RTL8814AE

*Note: USB and SDIO variants are currently unsupported/untested.*

## Features

- Native scanning of 2.4GHz and 5GHz bands.
- Connection to Open and WPA2 (CCMP/PSK) networks.
- Full 802.11n / 802.11ac hardware rate configuration using a `mac80211` compatibility shim.
- Custom `rtw88ctl` command-line utility to control the driver.

## Build Instructions

To build Feixiao from source, you will need the Xcode Command Line Tools and the macOS Kernel SDK.

```sh
# Clone the repository
git clone https://github.com/thegwchr/Feixiao.git
cd Feixiao

# Build the kext and control utility
make all
```

The compiled kernel extension (`rtw88.kext`) and the command-line utility (`rtw88ctl`) will be generated in the `build/out/` directory.

## Installation & Usage

1. **Load the Kext:**
   To load it manually for testing:
   ```sh
   sudo chown -R root:wheel build/out/rtw88.kext
   sudo kextload build/out/rtw88.kext
   ```
   *(You may be prompted to approve the extension in System Settings -> Privacy & Security. If you are using a Hackintosh, you can inject it via OpenCore).*

2. **Check Status:**
   Use the built-in control utility to check if the driver successfully initialized your card:
   ```sh
   ./build/out/rtw88ctl status
   ```

3. **Scan for Networks:**
   ```sh
   # Trigger a hardware scan
   ./build/out/rtw88ctl scan
   
   # List the discovered access points
   ./build/out/rtw88ctl list
   ```

4. **Connect to a Network:**
   ```sh
   ./build/out/rtw88ctl connect "Your_SSID" "Your_Password"
   ```

## Troubleshooting

You can view driver logs using the `rtw88ctl` tool or `dmesg`:
```sh
./build/out/rtw88ctl log
```

If you encounter kernel panics or connection failures, ensure you are using the latest commit and that your specific card's PCI ID is bound to the driver.

## Acknowledgements

- **Realtek** for the original Linux `rtw88` driver source code and WLAN card.
- **Apple** for the OS
- **AcidAnthera** for MacKernelSDK
- **OpenIntelWireless** for itlwm as reference
- The Hackintosh community for their continued inspiration in macOS driver development.
