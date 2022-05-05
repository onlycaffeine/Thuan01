# Thuan_01
Thuan_01 is a parallelized network login cracker tool.
It uses the dictionary search or Brute force method for cracking.
## Prerequisites
To run the app, minimal requirements are:
*	Python 3.3 or higher
*	debian-based linux distro, preferably Kali linux 2
*   Install figlet font "epic" if it does not exists on your system:
<br/> ```sudo wget http://www.figlet.org/fonts/epic.flf -O /usr/share/figlet/epic.flf```
## Disclaimer
This tool is only for testing and academic purposes Do not use it for illegal purposes!
## Features
*	Cracking using two methods:  **1.** dictionary method **2.** brute force method
*	In the brute force method, you can specify the min length and max length of the passwords.
*	 In the brute force method, you can specify the type of characters that may be used in the password.
*	There is a percent progress bar showing how much of the process has been performed.
*	Error handling.
*	One of the most important features of Thuan_01 is the multiprocessing feature that speeds up the program. For example if you have 8 CPU cores, Thuan_01 will use all of them for processing at the same time.
## Installation
Download Thuan_01 by cloning the Git repository:
  <br />```$ git clone https://github.com/onlycaffeine/Thuan01.git```
  
## Usage
To get a list of all options and learn how to use this app, enter the following command:<br />
  <br />```$ python3 Thuan_01.py -h```
  <br /><br /> 	
  ![alt text](https://github.com/onlycaffeine/images/blob/main/help.png)
## Examples
**1- Dictionary search to find the password for a get-form-login**
<br />In this example I use my own dictionary
<br /><br />```$ python3 Thuan_01.py -a 'dictionary' -u 'admin' -P mypass.txt -l 'http://127.0.0.1/dvwa/vulnerabilities/brute/?username=^USER^&password=^PASS^&Login=Login#' -M 'get-form' -c '{"PHPSESSID": "sr3beunfrqftno2mptm98bsuik", "security": "low"}' -f 'incorrect'```<br /><br />
![alt text](https://github.com/onlycaffeine/images/blob/main/dictionary-get-form.png)
 
**2- Brute force search to find the password for a post-form-login**
<br />Minimum length of password is 3 and maximum length is 3 and we try to find passwords that are composed of numbers.
<br /><br />```$ python3 Thuan_01.py -a 'bruteforce' -p 'thuanz1' -U digits -m 3 -x 3 -M 'post-form' -l 'http://testasp.vulnweb.com/Login.asp?RetURL=%2FDefault%2Easp%3F' -d '{"tfUName": ^USER^, "tfUPass": ^PASS^}' -f 'Invalid'```<br /><br />
![alt text](https://github.com/onlycaffeine/images/blob/main/bruteforce-post-form.png)

## Author

* **Thuan Nguyen** 

A special thank to, [Hamed Izadi](https://github.com/hamedeasy)
 		

