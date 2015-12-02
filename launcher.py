#!/usr/bin/env python

from fuse import FUSE, FuseOSError, Operations
from enc_fs import EncFs
import sys

def main(mountpoint, root, encryption_password_in, signing_password_in):
    opts = {
        'enc_pass': encryption_password_in,
        'sign_pass': signing_password_in
    }
    FUSE(EncFs(root, opts), mountpoint, nothreads=True, foreground=True)

def print_usage():
    print("Usage: enc_fs.py rootdir mountdir encryptionpassword signingpassword")

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print_usage()
        exit()

    main(sys.argv[2], sys.argv[1], sys.argv[3], sys.argv[4])
