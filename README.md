## Nordic  BLE DFU Bootloader

#### Overview

Two devices are involved when performing a Device Firmware Update (DFU). The DFU controller is the device that transfers the image. For instance, the DFU controller can be an app on a mobile phone. The DFU target device will be updated with a new firmware image, which can contain a new application, SoftDevice, bootloader, or a combination of SoftDevice and bootloader. 

Containing a bootloader with DFU capabilities, bootloader takes the responsibility to start either the application or the DFU mode. The DFU module is part of the bootloader. If DFU mode is started successfully, the DFU controller will initiate the transfer of a firmware image. The firmware image will then be validated by the bootloader and will replace the existing firmware if it passes the validation. 

