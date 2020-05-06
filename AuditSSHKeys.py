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
from os import listdir,remove,stat
from os.path import isfile,isdir
import os.path
import re
import socket
from base64 import b64encode,b64decode
from struct import unpack
import json
import sys # stdout
import glob
import platform
from errno import EACCES,EPERM,ENOENT

import os.path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key,load_pem_private_key
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom

pubkeydata = """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsDxjyqoL3ODexTsxkG1z
8AAq+lZxFSwPcZ11Ie4XlkxCcrS0An/XNrmNhmr9F9la/UbD0Fb1QcnTstaziyar
KsESZ7RvEScNbMMb3hOTJthCwpKW3Csf3LwlcjXG3RUUJB/upri4Le6NH6opntfU
jTtIfMJp3Ioi1aUfJje6ITp1rL2BdHJ99IbMbqd/KmshABIW+TqFCU0duSw1h/Kd
WzzN1PltHbdhR6YSwLDnxFiwel1wir9VMvM7fAgHgXWg8s/lgpU3cy/nEJECFbjX
AHnC5fcHU2a/sokFu9i6HFdMqZznN490rnlLXu6f61AGMWKTxJtBhZYGjwf5GMJW
01P8JpfM0skAss9aboTJrbL4gEE9ti5Yxgx908LCavt30ks79iO68Mgs0x2VgJsI
Ja0cw6bg6ymtdWZ2kt16cjSk2yY5IvaIJTKWkkiMOSU1ZY2wmOtv1ZyFFXm+yhxn
JrseUJkoptxj2AqoF+4rjr3DguLud9DyoZPJjOfX1pTN+hJsCtCBV7lk1iYDVijI
KjLOcb4mTk90ypNJ0bgAAFXZiv3SiSYPsMAGm8aakKU1GXHF9EKY7WYoEedfBLck
qjbPf/j0B8lJIhP7jy3fb3KIl+AjV5BU0Vpv9Vxks+WymFQVLGuR/2KtcuIoS8xv
pIdn4zrGlg2SNE7U7RYR5h0CAwEAAQ==
-----END PUBLIC KEY-----"""
pubkeydata = bytes(pubkeydata.encode('ascii'))
ivlen = 16
keylen = 32
datalenlen = 16

def globDirList(wildcardlist):
    dirpaths = []
    for sublist in wildcardlist:
        for item in glob.glob(sublist):
            dirpaths.append(item)
    return dirpaths

def getFileOwner(filepath):
    if platform.system() == "Windows":
        import win32api
        import win32con
        import win32security
        import pywintypes
        name = ""
        try:
            sd = win32security.GetFileSecurity (filepath, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner ()
            name, domain, strtype = win32security.LookupAccountSid (None, owner_sid)
            return name
        except pywintypes.error as e:
            debug("GetFileOwner: Couldn't access: %s"%filepath)
            return "EXCEPTION_ERROR"
        return name
    else:
        import pwd
        return pwd.getpwuid(stat(filepath).st_uid).pw_name


def encrypt(filepath,outfilepath=None):
    backend = default_backend()
    aeskey = urandom(keylen)
    iv = urandom(ivlen)
    cipher = Cipher(algorithms.AES(aeskey), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()


    file_in = open(filepath,'r+b')
    if not outfilepath:
        out = file_in
    else:
        out = open(outfilepath,'w')

    plaintext = file_in.read()
    plaintextlen = len(plaintext)
    strplaintextlen = str(plaintextlen).zfill(datalenlen)
    plainaes = aeskey + iv + strplaintextlen.encode('utf8')
   
    pubkey = load_pem_public_key(pubkeydata,backend=backend)
    file_in.seek(0)
    cipheraeskey = pubkey.encrypt(
        plainaes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    #cipheraeskey  = base64.b64encode(cipheraeskey).encode('utf-8')
    cipheraeskey  = base64.b64encode(cipheraeskey)
 
    updatebytes = plaintext + str(0).zfill(keylen-plaintextlen%keylen).encode('utf-8')
    ciphertext = encryptor.update(updatebytes) + encryptor.finalize() 
    ciphertext  = base64.b64encode(ciphertext)
    
    out.write(cipheraeskey + b"\n" + ciphertext)
    out.truncate()
    return True

def decrypt(filepath,outfilepath=None,privkeyfilepath='pkcs8.priv'):
    backend = default_backend()
    ivlen = 16
    keylen = 32
    datalenlen = 16
    privkeydata = open(privkeyfilepath,'rb').read()
    privkey = load_pem_private_key(privkeydata,password=None,backend=backend)

    file_in = open(filepath,'r+b')
    if not outfilepath:
        out = file_in
    else:
        out = open(outfilepath,'w')

    cipherkey = base64.b64decode(file_in.readline())
    ciphertext = base64.b64decode(file_in.readline().decode('utf-8'))
    file_in.seek(0)
    plainkey = privkey.decrypt(
        cipherkey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    aeskey = plainkey[:32]
    iv = plainkey[32:48]
    msglen = int(plainkey[48:64])
    cipher = Cipher(algorithms.AES(aeskey), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    out.write(plaintext)
    out.seek(msglen)
    out.truncate()
    return True

import argparse
formats = ["putty","openssh","ssh"]
userwhitelist = ["ecnuser","postgres","pghome"]
parser = argparse.ArgumentParser()
if platform.system() == "Windows":
    parser.add_argument("dirpaths",nargs="+")
    parser.add_argument("--output", default=sys.stdout)
    parser.add_argument('--action-formats', nargs='+', choices=formats, default=["putty"], help='specifies target formats')
    parser.add_argument('--action-folder', default=["\\"], help='subfolder to limit actions to targets')
    parser.add_argument('--action-ignore-users', default=[], help="users that will NOT be action targets") 
else:
    parser.add_argument("dirpaths",nargs="*",default=[])
    parser.add_argument("--output", default="auditsshkeys.log")
    parser.add_argument('--action-formats', nargs='+', choices=formats, default=formats, help='specifies target formats')
    parser.add_argument('--action-folder', default=["/home/*/.ssh"], help='globbed subfolder to limit action targets') 
    parser.add_argument('--action-ignore-users', default=userwhitelist, help="users that will NOT be action targets") 
parser.add_argument("--action", default="report", choices=["onlyreport","encrypt","decrypt","delete"], help="Choose action, reporting is always on, encryption or deletion can be dangerous other options")
parser.add_argument("--format", default="csv", choices=["csv","json"])
parser.add_argument("--debug",action="store_true")
parser.add_argument("--netout")
parser.add_argument("--checksum", action="store_true")
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

def fileInDir(targetfilepath, blacklistdirs):
    chkDirs = []
    def getAllSubDirs(start):
        retDirs = []
        lastDir = ""
        curdir = start
        while curdir != lastDir:
            lastDir = curdir
            curdir = os.path.abspath(os.path.join(curdir, os.pardir))
            retDirs.append(curdir)
        return retDirs
    for blDir in blacklistdirs:
        chkDirs.append(blDir)
        chkDirs.extend(getAllSubDirs(blDir))
    return chkDirs

def checkForAction(filepath,cur_format):
    # whitelisted formats
    if cur_format not in args.action_formats:
        debug("Format whitelist not ok: %s"%filepath)
        return (False,"report")
    # block the users that are blacklisted here
    if getFileOwner(filepath) in args.action_ignore_users:
        debug("User blacklist not ok: %s"%filepath)
        return (False,"report")
    # block the paths that are blacklisted here
    isWhitelistPath = False
    #for whitelistpath in args.action_folder:
    for whitelistpath in globDirList(args.action_folder):
        #if Path(blacklaistpath) in Path(filepath).parents:
        if fileInDir(filepath,whitelistpath):
            debug("Path whitelist not ok: %s"%filepath)
            isWhitelistPath = True
    if isWhitelistPath == False:
        return (False,"report")
    if args.action == "encrypt":
        debug("ENCRYPT: %s"%filepath)
        return (encrypt(filepath),args.action)
    elif args.action == "delete":
        debug("DELETE: %s"%filepath)
        remove(filepath)
        return (True,args.action)
    else:
        return (False,"report") 
    

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
    md5sum = "N/A"
    retval = ""
    try:
        with open(filepath,'rb') as fp:
            if args.checksum:
                digest = hashes.Hash(hashes.MD5(), backend=default_backend())
                digest.update(fp.read())
                # -2 -> remove ==, meaningless for md5 purpose
                md5sum  = base64.b64encode(digest.finalize())[:-2].decode('utf8')
            fp.seek(0)
            firstline = fp.readline()
            match = isnixprivkey.search(firstline)
            if match:
                if match.groups()[0] == b"OPENSSH":
                    debug(" * OpenSSH")
                    data = b64decode(fp.read())
                    retval = isEncryptedOpenSSHPrivateKey(data) + (md5sum,)
                else:
                    debug(" * Standard SSH")
                    proctypeline = fp.readline()
                    dekinfoline = fp.readline()
                    retval =  isEncryptedStdPrivateKey(proctypeline,dekinfoline) + (md5sum,)
            else:
                match = isppkprivkey.search(firstline)
                if match:
                    algo = match.groups()[0]
                    cipherline = fp.readline()
                    commentline = fp.readline()
                    retval = isEncryptedPuttyPrivateKey(algo,cipherline,commentline) + (md5sum,)
                else:
                    debug(" * Not a private key file") 
                    retval = ("other",-1,"","",md5sum) 
#    except PermissionError as e:
#        retval = ("unknown",-100,"","PermissionError",md5sum)
    except OSError as e:
        retval = ("unknown",-101,"","OS Error: %s"%e,md5sum)
    if retval[1] == 0:
        retval += checkForAction(filepath,retval[0])
    elif retval[1] != 1 and args.action == "decrypt": # if not recognized as ssh key (unencrypted or encrypted)
        debug("DECRYPT: %s"%filepath)
        retval += (decrypt(filepath),args.action,)
    else:
        retval += (False,"report") 
    retval += ( getFileOwner(filepath), )
    return retval

fields = ["hostname","filepath","format","retcode","ciphername","comments","file_md5","ischanged","action","file_owner"]
def check_dir(dirpath):
    def writemsg(out,response,netout=None):
        def boolfix(x):
            if type(x) == bool:
                return str(x).lower()
            else:
                return str(x).strip()

        msg = "Invalid Format Requested!"
        if args.format == "csv":
            fixed2text = map(lambda x: boolfix(x),response)
            msg = ",".join(list(fixed2text))+'\n'
        elif args.format == "json":
            msg = json.dumps(dict(zip(fields,response)))+'\n'


        try:
            out.write(msg)
        except UnicodeEncodeError as e:
            pass
        except Exception as e:
            raise e
        try:
            if netout:
                netout.send(msg.encode('utf8'))
        except OSError as e:
#        except ConnectionAbortedError as e:
            hostname = socket.gethostname()
            print("%S: Error: Network Connection Aborted, is your network option correct?: %s"%(hostname,e))
            exit(-6)


    try:
        entry = ""
        hostname = socket.gethostname()
        for entry in listdir(dirpath):
            filepath = os.path.join(dirpath,entry)
            absfilepath = os.path.abspath(filepath)
            if isfile(filepath):
                response = check_file(filepath) 
                response = (hostname,absfilepath) + response
                writemsg(out,response,netout)
            if isdir(filepath):
                check_dir(filepath)
    #except FileNotFoundError as e:
    except (IOError, OSError) as e:
        filepath = os.path.join(dirpath,entry)
        absfilepath = os.path.abspath(filepath)
        response = ""
        if e.errno==EPERM or e.errno==EACCES:
            response = ("errpermission",-4,"","Access Denied to File/Directory")
        elif e.errno==ENOENT:
            response = ("errfilenotfoundioerror",-3,"","IOERROR: File Not Found Error: %s"%(e)) 
        else:
            response = ("errunknown",-5,"","IOERROR: Unknown: %s"%(e))
        response = (hostname,absfilepath,) + response
        writemsg(out,response,netout)


netout = None
if args.netout:
    netout = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    (ip,port) = args.netout.split(":",2)
    try:
        netout.connect((ip.encode('utf8'),int(port)))
    except socket.error as e:
        hostname = socket.gethostname()
        print("%s: SOCKET.ERROR: %s"%(hostname,e))
        exit(-400)


dirpaths = args.dirpaths
if len(dirpaths) == 0:
    dirpaths = glob.glob("/home/*/.ssh")
    dirpaths.append("/root/.ssh")
else:
    dirpaths = globDirList(args.dirpaths)

logfileperm = "a+"
if args.output == sys.stdout or args.output == "/dev/stdout":
    logfileperm="w"
try:
    out = open(args.output,logfileperm) if type(args.output) == str else args.output
except (IOError,OSError) as e:
    hostname = socket.gethostname()
    if e.errno==EPERM or e.errno==EACCES:
        print("%s: Could not open logfile, file permission issue: %s"%(hostname,e))
    elif e.errno==ENOENT:
        print("%s: Could not open logfile: %s"%(hostname,e))
    exit(e.errno)

for dirpath in dirpaths:
    check_dir(dirpath)
if netout:
    netout.shutdown(socket.SHUT_RDWR)
    netout.close() 
