# Released tools and scripts for Canon MF644

This repository contains the following files related to the exploit:

  * [exploit.py](exploit.py) : Python exploit working against firmware in version 10.02
  * [Makefile](Makefile) : Makefile used to assemble the ARM shellcode 
  * [shellcode_ninja.S](shellcode_ninja.S) : ARM shellcode used to receive and a display a picture from a TCP socket 
  * [memdump](memdump) : Dump from the firmware needed to build the exploit payload
  * [image_delivery.py](image_delivery.py) : Python script implementing the TCP server that will send a picture on a socket

The IDA Python loader script for handling Canon firmware format is [ida/loaders-canon.py](ida/loaders-canon.py)

The IDA Python script used to automatically rename functions is [ida/rename-bip.py](ida/rename-bip.py) (logging function must first be renamed as ``logf``)

> Note: The exploit is working only against firmware in version 10.02.
