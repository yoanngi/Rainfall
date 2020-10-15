# LEVEL 0

### Reconnaissance

On se connecte au level0 avec le password level0

On trouve un binaire:
```
level0@RainFall:~$ ls -la
total 737
dr-xr-x---+ 1 level0 level0     60 Mar  6  2016 .
dr-x--x--x  1 root   root      340 Sep 23  2015 ..
-rw-r--r--  1 level0 level0    220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level0 level0   3530 Sep 23  2015 .bashrc
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
-rw-r--r--  1 level0 level0    675 Apr  3  2012 .profile
evel0@RainFall:~$ file level0 
level0: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=0x85cf4024dbe79c7ccf4f30e7c601a356ce04f412, not stripped
```

Si on le lance, il segfault:

```
level0@RainFall:~$ ./level0 
Segmentation fault (core dumped)
```

En l'analysant avec r2, on voit qu'il segfault car le programme attend un argument et fait un atoi dessus:
```
	    0x08048ec3      83e4f0         and esp, 0xfffffff0
│           0x08048ec6      83ec20         sub esp, 0x20
│           0x08048ec9      8b450c         mov eax, dword [str]
│           0x08048ecc      83c004         add eax, 4
│           0x08048ecf      8b00           mov eax, dword [eax]
│           0x08048ed1      890424         mov dword [esp], eax        ; const char *str
│           0x08048ed4      e837080000     call sym.atoi               ; int atoi(const char *str)
│           0x08048ed9      3da7010000     cmp eax, 0x1a7              ; 423
│       ┌─< 0x08048ede      7578           jne 0x8048f58
```

Si la valeur retourné par atoi est 423, il nous ouvre un shell, testons ceci.

### Exploitation

```
level0@RainFall:~$ ./level0 423
$ id
uid=2030(level1) gid=2020(level0) groups=2030(level1),100(users),2020(level0)
$ cat .pass
cat: .pass: Permission denied
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```








