# snow_crash

## Connection

Pour se connecter, il suffit de faire `ssh level00@192.168.1.30` (Note : Faire attention l'ip peut changer) password : `level00`

## Level 00

First one, we find the file of the user `flag00` is the owner.
After that we `cat` one of the file. 
```bash
level00@SnowCrash:~$ cat $(find / -user flag00 2> /dev/null)
```

We found this inside `cdiiddwpgswtgt`.
After multiple test we can translate this using [rot13](https://gchq.github.io/CyberChef/#recipe=ROT13(true,true,false,11)&input=Y2RpaWRkd3Bnc3d0Z3Q).
After this we found the answer is `nottoohardhere`.

After that we have to log with `flag00` and give the password `nottoohardhere`.
When we are connected we just have to use `getflag`.

When we got the flag we have to connect to the next level.

## Level 01
Look at the file we found in the previous level.
Yes the name of the file is **john**. Let use [John the ripper](https://fr.wikipedia.org/wiki/John_the_Ripper).

```bash
level01@SnowCrash:~$ cat /etc/passwd | grep flag01
```

Install [John](https://www.openwall.com/john/) on your computer and give it the result of the previous command.

After copy the file execute `john`. In my case i'm using [kali](https://www.kali.org/). 
```bash
kali@kali:~$ john --wordlist passwd
kali@kali:~$ john --show passwd
```
After the second command you should have this result.
```bash
flag01:abcdefg:3001:3001::/home/flag/flag01:/bin/bash
1 password hash cracked, 0 left
```

After that we have to log with `flag01` and give the password `abcdefg`.
When we are connected we just have to use `getflag`.

When we got the flag we have to connect to the next level.