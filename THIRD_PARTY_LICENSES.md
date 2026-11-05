# Third-party components

Components of third parties included with nornRTOS, which are not part of the Licensed
Work under LICENSE.md and are licensed under their own terms.

| component | where | licence | notes |
|---|---|---|---|
| Espressif ESP32 WiFi libraries (libnet80211, libpp, libcore, libcoexist, libespnow, libmesh, libsmartconfig, libwapi) | nornWIFI/lib/esp32, nornSDK/lib/esp32/espressif | Espressif binary licence, nornWIFI/lib/LICENSE.esp32-wifi-lib | binary only, version in nornWIFI/lib/esp32/VERSION |
| Espressif ESP32 PHY library (libphy) and RTC library (librtc) | same | nornWIFI/lib/LICENSE.esp-phy-lib | binary only |
| Espressif coexistence library | same | nornWIFI/lib/LICENSE.esp-coex-lib | binary only |
| ESP-IDF headers for the radio API (esp_wifi.h, esp_wifi_types.h, esp_err.h, the esp_private and stub headers) and the regulatory and PHY calibration tables (nw_regulatory.c, nw_phy_init_data.c) | nornWIFI/include, nornWIFI/nw, nornSDK/include/nornWIFI/esp | Apache License 2.0, Espressif Systems (Shanghai) Co. Ltd. | from ESP-IDF v5.5.x |
| wpa_supplicant, ESP-IDF's port | nornWIFI/supplicant, built into libnwsupp.a | BSD-3-Clause, Jouni Malinen and contributors; ESP-IDF additions Apache License 2.0 | WPA/WPA2 personal with PMF only |
| newlib (libc) and libgcc of the xtensa-esp-elf toolchain | linked into ESP32 images | newlib: BSD and similar per file; libgcc: GPL-3.0 with the GCC Runtime Library Exception | toolchain runtime, not distributed as source here |
| avr-libc and libgcc of the AVR toolchain | linked into AVR images | avr-libc: BSD-3-Clause; libgcc: GPL-3.0 with the GCC Runtime Library Exception | toolchain runtime |
