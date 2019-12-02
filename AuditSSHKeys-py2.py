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
from __future__ import print_function
from os import listdir
from os.path import isfile,isdir
import os.path
import re
import socket
from base64 import b64encode,b64decode
from struct import unpack
import json
import sys # stdout

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("dirpaths",nargs="+")
parser.add_argument("--output", default=sys.stdout)
parser.add_argument("--format", default="csv", choices=["csv","json"])
parser.add_argument("--debug",action="store_true")
parser.add_argument("--netout", default="")
args = parser.parse_args()

blacklist_ciphernames = [ 'none' ]
blacklist_kdfnames = [ 'none' ]
isnixprivkey = re.compile(b'----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----')
isppkprivkey = re.compile(b'^PuTTY-User-Key-File-2: (.*)$')
dekmatch = re.compile(b'DEK-Info: (.*)')
cryptoppkmatch = re.compile(b'Encryption: (.*)')
commentppkmatch = re.compile(b'Comment: (.*)')

def debug(*pargs,**kwargs):
    if args.debug:
        return print(*pargs,**kwargs)
    return

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
            debug(" * NOT Encrypted!")
            return ("openssh",0,strciphername,strkdfname)
        else:
            debug(" * Encrypted!")
            debug(" * Algorithms: %s %s"%(strciphername,strkdfname))
            return ("openssh",1,strciphername,strkdfname)
    else:
        return ("openssh-other",-2,"","")

def isEncryptedStdPrivateKey(proctypeline,dekinfoline):
# 1. Find "-----BEGIN (RSA\|EC\|DSA) PRIVATE KEY-----"
# 2. Look for "Proc-Type: 4,ENCRYPTED" on next line
# 3. Record "DEK-Info: .*" line
# 4. if missing 4,ENCRYPTED, then unencrypted,bad
    if "Proc-Type: 4,ENCRYPTED".upper() in proctypeline.decode('utf8').upper():
        match = dekmatch.search(dekinfoline)
        debug(" * Encrypted!")
        if match:
            dekstring = match.groups()[0].decode('utf8')
            debug(" * Algorithms: %s"%dekstring)
        return ("ssh",1,dekstring,"")
    debug(" * NOT Encrypted!")
    return ("ssh",0,"","")

def isEncryptedPuttyPrivateKey(also,cipherline,commentline):
    match = cryptoppkmatch.search(cipherline)
    ciphername = "none"
    comment = ""
    retval = 0
    debug(" * Putty SSH")
    if match:
        comment = ''
        ciphername = match.groups()[0].decode('utf8').strip()
        if ciphername != 'none':
            debug(" * Encrypted!")
            retval = 1
        else:
            debug(" * NOT Encrypted!")
            retval = 0
        debug(" * Algorithms: %s"%ciphername) 
        recomment = commentppkmatch.search(commentline)
        if recomment:
            comment = recomment.groups()[0].decode('utf8')
            debug(" * Comment: %s"%comment) 
    return ("putty",retval,ciphername,comment)
        
def check_file(filepath):
    debug("Opening %s"%(filepath))
    with open(filepath,'rb') as fp:
        firstline = fp.readline()
        match = isnixprivkey.search(firstline)
        if match:
            if match.groups()[0] == b"OPENSSH":
                debug(" * OpenSSH")
                data = b64decode(fp.read())
                return isEncryptedOpenSSHPrivateKey(data)
            else:
                debug(" * Standard SSH")
                proctypeline = fp.readline()
                dekinfoline = fp.readline()
                return isEncryptedStdPrivateKey(proctypeline,dekinfoline)
        match = isppkprivkey.search(firstline)
        if match:
            algo = match.groups()[0]
            cipherline = fp.readline()
            commentline = fp.readline()
            return isEncryptedPuttyPrivateKey(algo,cipherline,commentline)
        debug(" * Not a private key file") 
        return ("other",-1,"","") 

fields = ["hostname","path","format","returncode","ciphername","comments"]
def check_dir(dirpath):
    for entry in listdir(dirpath):
        filepath = os.path.join(dirpath,entry)
        if isfile(filepath):
            response = check_file(filepath) 
            response = (socket.gethostname(),os.path.abspath(filepath),) + response
            msg = "Invalid Format Requested!"
            if args.format == "csv":
                msg = ",".join(map(lambda x: str(x),response))+'\n'
            elif args.format == "json":
                msg = json.dumps(dict(zip(fields,response)))+'\n'
            out.write(msg)
            if netout:
                netout.send(msg.encode('utf8'))
            
        if isdir(filepath):
            check_dir(filepath)

netout = None
if args.netout:
    netout = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    (ip,port) = args.netout.split(":",2)
    netout.connect((ip.encode('utf8'),int(port)))

out = open(args.output,"w") if type(args.output) == str else args.output
for dirpath in args.dirpaths:
    check_dir(dirpath)
if netout:
    netout.shutdown(socket.SHUT_RDWR)
    netout.close() 
