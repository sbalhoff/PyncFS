from __future__ import with_statement
from fuse import FUSE, FuseOSError, Operations
from encryptionstore import retrieve_key
from encryption import encrypt, decrypt, padding_length
import os

from meta_fs import MetaFs
from util import *

class EncFs(MetaFs):
    enc_keymatter_file = '.enc_keymatter'
    sign_keymatter_file = '.sign_keymatter'
    
    def __init__(self, root, opts):
        MetaFs.__init__(self, root, opts)
        self.encryption_key = retrieve_key(opts['enc_pass'], self._full_path(self.enc_keymatter_file))
        self.signing_key = retrieve_key(opts['sign_pass'], self._full_path(self.sign_keymatter_file))
        self.cypher = BlockCypher(self.encryption_key, self.signing_key)

        #todo: securely delete passwords
        enc_pass = ''
        sign_pass = ''

    def set_empty_meta(self, path):
        m_data = {
            'empty': True
        }
        self.write_metadata_file(path, m_data)

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
        # Write meta here for consistency
        self.set_empty_meta(path)
        return f

    def truncate(self, path, length, fh=None):
        super(EncFs, self).truncate(path, length, fh)
        self.set_empty_meta(path)

    def read(self, path, length, offset, fh):
        if self.is_blacklisted_file(path):
            raise IOError()

        metadata = self.read_meta_file(path)
        return self.cypher.read_file(path, length, offset, fh, metadata)

    def write(self, path, buf, offset, fh):
        if self.is_blacklisted_file(path):
            raise IOError

        print("write %s len: %s offset: %s" % (path, len(buf), offset))

        old_metadata = self.read_meta_file(path)
        res = self.cypher.write_file(self._full_path(path), buf, offset, old_metadata)
        new_meta = res[1]
        self.write_metadata_file(path, new_meta)
        num_written = res[0]
        return num_written


class BlockCypher():
    group_block_multiple = 10
    block_size = 16

    metadata_header_length = 80
    digest_size = 64
    iv_size = 16

    def __init__(self, enc_key, sign_key):
        self.group_block_size = self.block_size * self.group_block_multiple

        self.encryption_key = enc_key
        self.signing_key = sign_key

    # Returns tuple of (encrypted_data, metadata)
    def encrypt_block(self, data):
        enc_data = encrypt(data, self.encryption_key, self.signing_key)
        meta = self.get_block_metadata(data, enc_data)
        return (enc_data, meta)

    def get_block_metadata(self, plain_data, enc_data):
        padlength = padding_length(len(plain_data))
        digest = enc_data[0:self.digest_size]
        iv = enc_data[self.digest_size:self.digest_size+self.iv_size]
        m_data = {
            'digest': digest,
            'iv': iv,
            'padding': enc_data[(-1 * padlength):],
            'pad_len': padlength
        }
        return m_data

    def decrypt_with_metadata(self, data, metadata):
        data = metadata['digest'] + metadata['iv'] + data + metadata['padding']
        return decrypt(data, self.encryption_key, self.signing_key)

    def read_file(self, path, length, offset, fh, metadata):
        print("read "+ path)
        os.lseek(fh, 0, os.SEEK_SET)

        readlength = offset + length
        if readlength % self.block_size != 0:
            readlength = readlength + self.block_size - readlength % self.block_size

        data = os.read(fh, readlength)
        if len(data) > 0:
            data = self.decrypt_with_metadata(data, metadata)

        return data[offset:(offset + length)]

    def write_file(self, path, buf, offset, metadata):
        #compute the entire plaintext to be written to the file
        #currently does not support writing less than the entire file
        plaintext = buf
        try:
            with open(path, 'r') as f:
                data = f.read()
                #prevent useless metadata files. should clean them on deletes / truncates
                if len(data) > 0:
                    # Skipped data is 0 so don't decrypt
                    if not is_all_zero(data) and offset != 0:
                        data = self.decrypt_with_metadata(data, metadata)
                    plaintext = data[:offset] + buf + data[(offset + len(buf)):]

        except IOError:
            plaintext = buf
        
        #encrypt and write the metadata file
        enc_block = self.encrypt_block(plaintext)
        enc_data = enc_block[0]
        metadata = enc_block[1]

        #write the actual file. The first 80 bytes of filedata are the 
        #hex digest + the iv. The last "padlength" bytes are block padding
        write_data = enc_data[self.metadata_header_length:(-1*metadata['pad_len'])]
        with open(path, 'wb') as f:
            f.write(write_data)

        bytes_written = len(write_data)
        sze = min(len(buf), bytes_written)

        return (sze, metadata)
