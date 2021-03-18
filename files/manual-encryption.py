#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Schranz Guillaume & Lièvre Loïc"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "guillaume.schranz@heig-vd.ch, loic.lievre@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
import binascii
from rc4 import RC4

#Cle wep AA:AA:AA:AA:AA
key= b'\xaa\xaa\xaa\xaa\xaa'

text = "aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8"

# chiffrement rc4
cipher = RC4(seed, streaming=False)
encryptedText=cipher.crypt(message_encrypted)

print(encryptedText)