from __future__ import with_statement
from fuse import FUSE, FuseOSError, Operations
from encryptionstore import retrieve_key

from meta_fs import MetaFs
from file_metadata import FileMetaData
from block_cipher import BlockCipher
from util import *

class EncFs(MetaFs):
    enc_keymatter_file = '.enc_keymatter'
    sign_keymatter_file = '.sign_keymatter'

    def __init__(self, root, opts):
        MetaFs.__init__(self, root, opts)
        self.encryption_key = retrieve_key(opts['enc_pass'], self._full_path(self.enc_keymatter_file))
        self.signing_key = retrieve_key(opts['sign_pass'], self._full_path(self.sign_keymatter_file))
        self.cipher = BlockCipher(self.encryption_key, self.signing_key)

        #todo: securely delete passwords
        enc_pass = ''
        sign_pass = ''

    def is_key_file(self, partial):
        partial = self._without_leading_slash(partial)
        return partial == self.enc_keymatter_file or partial == self.sign_keymatter_file

    def is_blacklisted_file(self, partial):
        return self.is_key_file(partial) or super(EncFs, self).is_blacklisted_file(partial)

    # ============
    # File methods
    # ============

    def create(self, path, mode, fi=None):
        f = super(EncFs, self).create(path, mode, fi)
        # Write clear meta here for consistency
        #self.set_empty_meta(path, True)
        with self.with_meta_obj(path) as o:
            o.set_empty(True)

        return f

    # TODO finish metedata updates on truncate
    def truncate(self, path, length, fh=None):
        super(EncFs, self).truncate(path, length, fh)

        with self.with_meta_obj(path) as o:
            o.set_length(length)
            o['truncated'] = True

            #if length == 0:
            #    o.set_empty(True)


    def read(self, path, length, offset, fh):
        if self.is_blacklisted_file(path):
            raise IOError()

        metadata = self.get_meta_obj(path)
        return self.cipher.read_file(path, length, offset, fh, metadata)

    def write(self, path, buf, offset, fh):
        if self.is_blacklisted_file(path):
            raise IOError

        print("write %s len: %s offset: %s" % (path, len(buf), offset))

        metadata = self.get_meta_obj(path)
        res = self.cipher.write_file(self._full_path(path), buf, offset, metadata)
        self.update_meta_on_write(metadata, res)
        num_written = res[0]
        return num_written

    def update_meta_on_write(self, metadata, res):
        new_meta = res[1]
        num_written = res[0]

        # Clear truncation after write
        if 'truncated' in metadata:
            metadata['truncated'] = False

        # Update len
        metadata.set_length(new_meta['length'])
        metadata.update(new_meta)

        # Check empty
        if num_written > 0:
            metadata['empty'] = False

        # Save
        self.save_meta_obj(metadata)
