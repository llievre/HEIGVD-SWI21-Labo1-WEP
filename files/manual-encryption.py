#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

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
key = b'\xaa\xaa\xaa\xaa\xaa'

#reprend la trame du fichier pour la modifier
arp = rdpcap('arp.cap')[0]

#on assigne des valeurx hexa au texte
text = bytes.fromhex("aaaa03000000080600010800060400019027e4ea61f2c0a80164000000000000c0a801c8")

#seed avec l'iv contenu dans le modele de trame et la clé définie
#nous aurions pu definir un autre iv selon les infos du cours en slide 25 du pdf WEP
seed = arp.iv+key

#calcul de l'icv avec le crc32
icv = binascii.crc32(text).to_bytes(4, byteorder='little')

# chiffrement rc4
cipher = RC4(seed, streaming=False)
encryptedText = cipher.crypt(text + icv)
 
#on complete la trame avec les wepdata et l'icv calculé
arp.wepdata = encryptedText[:-4]
icv_enclair = encryptedText[-4:]
arp.icv = struct.unpack('!L', icv_enclair)[0]

#écris le fichier
wrpcap("step2.pcap", arp)