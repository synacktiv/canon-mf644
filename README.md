# Released tools and scripts for Canon MF644

## Exploit for Pwn2Own 2021 - Vulnerability in CADM (firmware 10.02)

This repository contains the following files related to the exploit:

  * [exploit.py](exploit_cadm/exploit.py) : Python exploit working against firmware in version 10.02
  * [Makefile](exploit_cadm/Makefile) : Makefile used to assemble the ARM shellcode
  * [shellcode_ninja.S](exploit_cadm/shellcode_ninja.S) : ARM shellcode used to receive and a display a picture from a TCP socket
  * [memdump](exploit_cadm/memdump) : Dump from the firmware needed to build the exploit payload

> Note: The exploit is working only against firmware in version 10.02.

## Exploit for Pwn2Own 2022 - Vulnerability in NetBIOS service (firmware 11.04)

  * [exploit.py](exploit_netbios/exploit.py) : Python exploit working against firmware in version 11.04
  * [Makefile](exploit_netbios/Makefile) : Makefile used to assemble the ARM shellcode
  * [shellcode_ninja.S](exploit_netbios/shellcode_ninja.S) : ARM shellcode used to receive and a display a picture from a TCP socket

> Note: The exploit is working only against firmware in version 11.04

## MISC

  * [image_delivery.py](image_delivery.py) : Python script implementing the TCP server that will send a picture on a socket

## IDA Python script

The IDA Python loader script for handling Canon firmware format is [ida/loaders-canon.py](ida/loaders-canon.py)

The IDA Python script used to automatically rename functions is [ida/rename-bip.py](ida/rename-bip.py) (logging function must first be renamed as ``logf``)

