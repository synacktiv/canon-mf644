#!/usr/bin/env python3

from PIL import Image
import socket
import argparse
import os

IMAGE_NAME = "synacktiv_logo_800_480.png"
SERVER_PORT = 9000
SERVER_ADDR = "0.0.0.0"
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 480

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--picture",
        help=f"Picture to display (resolution must be {SCREEN_WIDTH}x{SCREEN_HEIGHT})",
        default=IMAGE_NAME,
    )
    args = parser.parse_args()

    with Image.open(args.picture) as im:
        if im.width != SCREEN_WIDTH or im.height != SCREEN_HEIGHT:
            raise Exception(
                f"Please resize your image to {SCREEN_WIDTH}x{SCREEN_HEIGHT}"
            )
        px = im.load()
    rgb_pixel_array = bytearray(SCREEN_WIDTH * SCREEN_HEIGHT * 3)

    i = 0
    while i < (SCREEN_WIDTH * SCREEN_HEIGHT):
        x = i % SCREEN_WIDTH
        y = i // SCREEN_WIDTH
        pixel = px[x, y]
        rgb_pixel_array[i * 3] = pixel[0]
        rgb_pixel_array[i * 3 + 1] = pixel[1]
        rgb_pixel_array[i * 3 + 2] = pixel[2]
        i += 1

    print("Image pixels loaded...")

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(f"Binding on {SERVER_ADDR}:{SERVER_PORT}...")
    serversocket.bind((SERVER_ADDR, SERVER_PORT))
    serversocket.listen(1)

    print("Waiting for connection from compromised printer...")
    (clientsocket, address) = serversocket.accept()
    print(f"Received connection from {address}...")
    while True:
        clientsocket.sendall(rgb_pixel_array)
