# Password-Sniffer
Password-Sniffer coded in Python 3.10.2.  

DISCLAIMER:

- I am not responsible with your illegal intentions with this so don't use this on someone explicitly without their permission.

Third Party Modules:

- scapy
- colorama

Installation:

1. Just clone this or download this as a zip:
- git clone https://github.com/Anz1x/Password-Sniffer

2. Install the modules
- pip3 install -r requirements.txt

3. Give execution permissions
- chmod +x passwordsniffer.py

Usage:

In order to use this you first need to run the file and specify 2 arguments: the router and the target (in order)
./passwordsniffer.py <your network interface>

EXAMPLE: ./passwordsniffer.py eth0

The program will keep running so it won't stop by itself so if you want to stop the program just use the keyboard shortcut ctrl + c

If you want to steal credentials from everyone in the network then for now just run the arpsoofer first https://github.com/Anz1x/Arp-Spoofer and then run the password sniffer, later I might put everything in a 1 big program
