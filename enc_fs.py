#!/usr/bin/env python

from __future__ import with_statement

from encryptionstore import retrieve_key
from encryption import encrypt, decrypt, padding_length

import os
import sys
import errno
import hashlib

from fuse import FUSE, FuseOSError, Operations

enc_keymatter_file = '.enc_keymatter'
sign_keymatter_file = '.sign_keymatter'

encryption_password = ''
signing_password = ''

class Passthrough(Operations):
    def __init__(self, root):
        global encryption_password
        global signing_password
        global enc_keymatter_file
        global sign_keymatter_file
        self.root = root
        self.encryption_key = retrieve_key(encryption_password, self._full_path(enc_keymatter_file))
        self.signing_key = retrieve_key(signing_password, self._full_path(sign_keymatter_file))
        self.metadata_header_length = 80

        #todo: securely clear the passwords
        encryption_password = ''
        signing_password = ''

    # Helpers
    # =======

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def _metadata_filename(self, partial):
        return '.' + hashlib.md5(partial).hexdigest()

    def _metadata_file(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]

        #has a race condition, but good enough for now
        metadatadir = os.path.join(self.root, 'metadata')
        if not os.path.exists(metadatadir):
            os.makedirs(metadatadir)

        return os.path.join(metadatadir, self._metadata_filename(partial))

    # Filesystem methods
    # ==================

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def chmod(self, path, mode):
        full_path = self._full_path(path)
        return os.chmod(full_path, mode)

    def chown(self, path, uid, gid):
        full_path = self._full_path(path)
        return os.chown(full_path, uid, gid)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        st = os.lstat(full_path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                     'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    def readdir(self, path, fh):
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            if not self.is_blacklisted(os.path.join(path, r)):
                yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def mknod(self, path, mode, dev):
        print('mknod: ' + path)
        return os.mknod(self._full_path(path), mode, dev)

    def rmdir(self, path):
        full_path = self._full_path(path)
        return os.rmdir(full_path)

    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def unlink(self, path):
        return os.unlink(self._full_path(path))

    def symlink(self, name, target):
        print('symlink')
        return os.symlink(name, self._full_path(target))

    def rename(self, old, new):
        os.rename(self._metadata_file(old), self._metadata_file(new))
        return os.rename(self._full_path(old), self._full_path(new))

    def link(self, target, name):
        print('link')
        print('target: ' + target)
        print('name: ' + name)
        return os.link(self._full_path(target), self._full_path(name))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)

    # File methods
    # ============

    def decrypt_with_metadata(self, path, data):
        print('decrypt path: ' + path)
        metafilepath = self._metadata_file(path)
        metafile = open(metafilepath, 'r')
        metadata = metafile.read()
        data = metadata[:self.metadata_header_length] + data + metadata[self.metadata_header_length:]
        metafile.close()
        return decrypt(data, self.encryption_key, self.signing_key)

    #enc_data format: 64 byte digest, 16 byte iv, actual encrypted data, padding on the end
    def write_metadata_file(self, path, enc_data, padlength):
        metafilepath = self._metadata_file(path)
        metafile = open(metafilepath, 'w')
        metafile.write(enc_data[0:self.metadata_header_length] + enc_data[(-1 * padlength):])

    def is_blacklisted(self, partial):
        global enc_keymatter_file
        global sign_keymatter_file
        if partial.startswith("/"):
            partial = partial[1:]
        
        return partial == enc_keymatter_file or partial == sign_keymatter_file or partial.startswith('metadata')

    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        print('create: ' + path)
        full_path = self._full_path(path)
        return os.open(full_path, os.O_RDWR | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        print('read offset: %d' % (offset))
        os.lseek(fh, offset, os.SEEK_SET)
        data = os.read(fh, length)
        if not self.is_blacklisted(path) and len(data) > 0:
            data = self.decrypt_with_metadata(path, data)
        return data

    def write(self, path, buf, offset, fh):
        print('writing to: ' + path)

        fullpath = self._full_path(path)

        if self.is_blacklisted(path):
            os.lseek(fh, offset, os.SEEK_SET)
            return os.write(fh, buf)

        #compute the entire plaintext to be written to the file
        #currently does not support writing less than the entire file
        plaintext = buf
        try:
            f = open(fullpath, 'r')
            data = f.read()

            #prevent useless metadata files. should clean them on deletes / truncates
            if len(data) > 0:
                data = self.decrypt_with_metadata(path, data)
                plaintext = data[:offset] + buf + data[(offset + len(buf)):]
            f.close()
        except IOError:
            plaintext = buf
        
        #encrypt and write the metadata file
        filedata = encrypt(plaintext, self.encryption_key, self.signing_key)
        padlength = padding_length(len(plaintext))
        self.write_metadata_file(path, filedata, padlength)

        #write the actual file. The first 80 bytes of filedata are the 
        #hex digest + the iv. The last "padlength" bytes are block padding
        os.lseek(fh, 0, os.SEEK_SET)
        bytes_written = os.write(fh, filedata[self.metadata_header_length:(-1*padlength)])
        return min(len(buf), bytes_written)

    def truncate(self, path, length, fh=None):
        full_path = self._full_path(path)
        with open(full_path, 'r+') as f:
            f.truncate(length)

    def flush(self, path, fh):
        print('flush')
        return os.fsync(fh)

    def release(self, path, fh):
        return os.close(fh)

    def fsync(self, path, fdatasync, fh):
        print('fsync')
        print(fdatasync)
        return self.flush(path, fh)


def main(mountpoint, root, encryption_password_in, signing_password_in):
    global encryption_password
    global signing_password
    encryption_password = encryption_password_in
    signing_password = signing_password_in
    FUSE(Passthrough(root), mountpoint, nothreads=True, foreground=True)

def print_usage():
    print("Usage: enc_fs.py rootdir mountdir encryptionpassword signingpassword")

if __name__ == '__main__':
    if len(sys.argv) < 5:
        print_usage()
        exit()

    main(sys.argv[2], sys.argv[1], sys.argv[3], sys.argv[4])


