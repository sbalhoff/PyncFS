#!/usr/bin/env python

from __future__ import with_statement
from fuse import FUSE, FuseOSError, Operations
import os
import sys
import errno

from encryption_provider import BasicEncryption

encryption_password = ''
signing_password = ''

class Passthrough(Operations):
    def __init__(self, root):
        global encryption_password
        global signing_password
        self.root = root
        self.enc_provider = BasicEncryption(self, encryption_password, signing_password)

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
        print('symlink %s %s' % (target, name))
        return os.symlink(target, self._full_path(name))

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

    def is_blacklisted(self, partial):
        return self.enc_provider.is_blacklisted_file(partial)

    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        print('create: ' + path)
        full_path = self._full_path(path)
        return os.open(full_path, os.O_RDWR | os.O_CREAT, mode)

    def read(self, path, length, offset, fh):
        print('read offset: %d' % (offset))

        if self.is_blacklisted(path):
            os.lseek(fh, offset, os.SEEK_SET)
            return os.read(fh, length)

        return self.enc_provider.read(path, length, offset, fh)

    def write(self, path, buf, offset, fh):
        print('writing to: ' + path)

        if self.is_blacklisted(path):
            os.lseek(fh, offset, os.SEEK_SET)
            return os.write(fh, buf)

        return self.enc_provider.write(path, buf, offset, fh)

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
