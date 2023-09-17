# Pico-Scanner

This is a micropython port of the (original scanner code)[https://github.com/snacker-tracker/scanner]

It offers the same functionality, still no tests, but only requires a raspberry-pi pico. Changes are, this could run perfectly well on any ESP devices as well, but this is what I wanted to work with, and I didn't test anything else.

The one big change is that now the barcode scanner needs to support UART/TTL. Some barcodes will say they support UART/TTL, but what they might mean is that it has a USB-TTL chip on-board, without you being able to access the actual TTL signal from some of the pins.

(this scanner)[https://www.aliexpress.com/item/33036582612.html?spm=a2g0o.order_list.order_list_main.16.3338180282L2i6] from AlieExpress is just the ticket. It has TTL pins, and one can hack it for it to be powered from the USB cable, and hook-up the RPI-PICO to the TTL pins.

Additionally, it supports having the wifi connection re-configured by scanning the wifi sharing QR codes.
