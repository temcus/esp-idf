# ESP32 Compressed Delta OTA Updates

## About the Project

The project aims at enabling firmware update of ESP32 Over-the-Air with compressed delta binaries. Testing was done with ESP32-DevKitC v4 board.
## Getting Started

### Hardware Required

To run the OTA demo, you need an ESP32 dev board (e.g. ESP32-WROVER Kit) or ESP32 core board (e.g. ESP32-DevKitC).
You can also try running on ESP32-S2 or ESP32-C3 dev boards.

### Prerequisites

* **ESP-IDF v4.3 and above**

  You can visit the [ESP-IDF Programmming Guide](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/index.html#installation-step-by-step) for the installation steps.

* **detools v0.49.0 and above**

  Binary delta encoding in Python 3.6+. You can follow the instructions [here](https://pypi.org/project/detools/) for installation.

* **Partition Tool (parttool.py)**

  [parttool.py](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html#command-line-interface) comes pre-installed with ESP-IDF; it can be used after the ESP-IDF python venv is initialised - See [here](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/#step-4-set-up-the-environment-variables).


## Usage

1. Build the example `examples/http_delta_ota` and flash the partition table `partitions.csv`.

   `idf.py build && idf.py partition_table-flash`

2. To generate the patch, we need 2 application binaries, namely `base_binary` and `updated_binary`.

   `detools create_patch -c heatshrink base_binary.bin updated_binary.bin patch.bin`

3. Currently, patch application demo is supported only for the `ota_0` partition.  So, we need to flash the base binary to the `ota_0` partition.

   `parttool.py --port "/dev/ttyUSB0"  --baud 2000000 write_partition --partition-name=ota_0 --input="base_binary.bin"`

4. Open the project configuration menu (`idf.py menuconfig`) go to `Example Connection Configuration` ->
    1. WiFi SSID: WiFi network to which your PC is also connected to.
    2. WiFi Password: WiFi password

5. In order to test the OTA demo -> `examples/http_delta_ota` :
    1. Flash the firmware `idf.py -p PORT -b BAUD flash`
    2. Run `idf.py -p PORT monitor` and note down the IP assigned to your ESP module. The default port is 80.

6. After getting the IP address, send the patch binary through a HTTP Post request over cURL.

   `curl -v -X POST --data-binary @- < patch.bin 192.168.224.196:80/ota`

## Acknowledgements & Resources

- esp32_compressed_delta_ota_update: Starting point of this library [Source](https://github.com/ESP32-Musings/esp32_compressed_delta_ota_update)
- detool: Binary delta encoding in Python 3 and C 🡒 [Source](https://github.com/eerimoq/detools) | [Docs](https://detools.readthedocs.io/en/latest/)
- heatshrink: An Embedded Data Compression Library 🡒 [Source](https://github.com/atomicobject/heatshrink) | [Blog](https://spin.atomicobject.com/2013/03/14/heatshrink-embedded-data-compression/)
- Delta updates for embedded systems 🡒 [Source](https://gitlab.endian.se/thesis-projects/delta-updates-for-embedded-systems) | [Docs](https://odr.chalmers.se/bitstream/20.500.12380/302598/1/21-17%20Lindh.pdf)


## License

Distributed under the MIT License. See `LICENSE` for more information.
The bundled delta component uses an Apache license. See `components/delta/LICENSE` for more information.

