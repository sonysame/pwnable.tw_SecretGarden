# pwnable.tw_SecretGarden

1) Heap Leak  
fastbin & uaf를 이용한다. fast chunk를 free하면 fd에 그 다음 청크(fd)주소가 들어간다.  
즉, 힙 주소가 들어감을 이용해서 uaf로 그 자리에 데이터(널바이트)를 넣어줘서 heap leak이 가능하다.  

2) Libc Leak  
unsorted bin을 이용한다. unsorted chunk는 free를 하면 fd, bk에 main_arena+88의 주소가 들어간다.    
즉, libc영역의 주소가 fd, bk에 들어가는 것이므로 이 또한 uaf를 이용해서 libc leak이 가능하다.  

여기서부터는 여러 가지 풀이가 존재한다.   

3-1) malloc_hook을 one_gadget으로 덮기!(sol1)   
malloc_hook-35위치를 이용(0x7f)  <-"a"*19+one_gadget  
만약, one_gadget조건이 맞지 않는다고 하더라도, free에서 에러를 내서 malloc_printerr이 불러지면 one_gadget이 불러진다.  

3-2) stdout의 vtable을 one_gadget으로 덮기!(sol3)  
stdout의 vtable은 _IO_2_1_stdout+216이다.    
이 곳에 주로 _IO_file_jumps가 들어가 있고,  
call   QWORD PTR [rax+0x38] 에 의해 _IO_file_jumps+0x38이 불러진다.  
이때, 
_IO_2_1_stdout+216: IO_2_1_stdout+208-0x38  
IO_2_1_stdout+208: one_gadget   
을 넣어서 one_gadget을 실행시켜줄 수 있다!!  
