#!/usr/bin/python36

# Technique:
# 1. Find "-----BEGIN (RSA\|EC\|DSA) PRIVATE KEY-----"
# 2. Look for "Proc-Type: 4,ENCRYPTED" on next line
# 3. Record "DEK-Info: .*" line
# 4. if missing 4,ENCRYPTED, then unencrypted,bad
# 
# OR 
#
# 1. Find "-----BEGIN OPENSSH PRIVATE KEY-----"
# 2. Base64 decode the rest (until ----END OPENSSH PRIVATE KEY)
# 3. look for beginning "openssh-key-v1\0"
# 4. Grab next 4 bytes as 32bit value, grab next null string as ciphername
# 5. Grab next 4 bytes as 32bit value, grabe next null string as kdfname
# 6. if ciphername not "none" and kdfname not "none" then gtg..
# 7. stop... we could do more, but there's no point
#

from os import listdir
from os.path import isfile
import os.path
import re
from base64 import b64encode,b64decode
from struct import unpack

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("dirpaths",nargs="+")
args = parser.parse_args()

blacklist_ciphernames = [ 'none' ]
blacklist_kdfnames = [ 'none' ]
isnixprivkey = re.compile(b'----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----')
isppkprivkey = re.compile(b'^PuTTY-User-Key-File-2: (.*)$')
dekmatch = re.compile(b'DEK-Info: (.*)')
cryptoppkmatch = re.compile(b'Encryption: (.*)')
commentppkmatch = re.compile(b'Comment: (.*)')

def isEncryptedOpenSSHPrivateKey(data):
    sig = b"openssh-key-v1\0"
    if sig in data[0:len(sig)]:
        data = data[len(sig):]

        numciphername = unpack('I',data[:4])
        data = data[4:]
        strciphername = data.split(b'\0', 1)[0].decode('utf8')
        data = data[len(strciphername):]

        numkdfname = unpack('I',data[:4])
        data = data[4:]
        strkdfname = data.split(b'\0', 1)[0].decode('utf8')
        
        if strciphername in blacklist_ciphernames or strkdfname in blacklist_kdfnames:
            print(" * NOT Encrypted!")
            return 0
        else:
            print(" * Encrypted!")
            print(" * Algorithms: %s %s"%(strciphername,strkdfname))
            return 1
    else:
        return -2

def isEncryptedStdPrivateKey(proctypeline,dekinfoline):
# 1. Find "-----BEGIN (RSA\|EC\|DSA) PRIVATE KEY-----"
# 2. Look for "Proc-Type: 4,ENCRYPTED" on next line
# 3. Record "DEK-Info: .*" line
# 4. if missing 4,ENCRYPTED, then unencrypted,bad
    if "Proc-Type: 4,ENCRYPTED".upper() in proctypeline.decode('utf8').upper():
        match = dekmatch.search(dekinfoline)
        print(" * Encrypted!")
        if match:
            dekstring = match.groups()[0].decode('utf8')
            print(" * Algorithms: %s"%dekstring)
        return 1
    print(" * NOT Encrypted!")
    return 0

def isEncryptedPuttyPrivateKey(also,cipherline,commentline):
    match = cryptoppkmatch.search(cipherline)
    retval = 0
    print(" * Putty SSH")
    if match:
        comment = ''
        ciphername = match.groups()[0].decode('utf8').strip()
        if ciphername != 'none':
            print(" * Encrypted!")
            retval = 1
        else:
            print(" * NOT Encrypted!")
            retval = 0
        print(" * Algorithms: %s"%ciphername) 
        recomment = commentppkmatch.search(commentline)
        if recomment:
            comment = recomment.groups()[0].decode('utf8')
            print(" * Comment: %s"%comment) 
    return retval

        
def check_file(filepath):
    print("Opening %s"%(filepath))
    with open(filepath,'rb') as fp:
        firstline = fp.readline()
        match = isnixprivkey.search(firstline)
        if match:
            if match.groups()[0] == b"OPENSSH":
                print(" * OpenSSH")
                data = b64decode(fp.read())
                return isEncryptedOpenSSHPrivateKey(data)
            else:
                print(" * Standard SSH")
                proctypeline = fp.readline()
                dekinfoline = fp.readline()
                return isEncryptedStdPrivateKey(proctypeline,dekinfoline)
        match = isppkprivkey.search(firstline)
        if match:
            algo = match.groups()[0]
            cipherline = fp.readline()
            commentline = fp.readline()
            return isEncryptedPuttyPrivateKey(algo,cipherline,commentline)
        print(" * Not a private key file") 
        return -1 


for dirpath in args.dirpaths:
    for entry in listdir(dirpath):
        filepath = os.path.join(dirpath,entry)
        if isfile(filepath):
            response = check_file(filepath) 

