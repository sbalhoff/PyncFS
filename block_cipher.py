from encryption import encrypt, decrypt, padding_length
import os
import math

from util import *

class BlockCipher():
    group_block_multiple = 10
    block_size = 16

    digest_size = 64
    iv_size = 16
    metadata_header_length = digest_size + iv_size

    def __init__(self, enc_key, sign_key):
        self.group_block_size = self.block_size * self.group_block_multiple

        self.encryption_key = enc_key
        self.signing_key = sign_key

    def get_nearest_block_size(self, size):
        return int(self.block_size * math.ceil(size / float(self.block_size)))

    # Returns tuple of (encrypted_data, metadata)
    def encrypt_data(self, data):
        enc_data = encrypt(data, self.encryption_key, self.signing_key)
        meta = self.get_metadata(data, enc_data)
        return (enc_data, meta)

    def get_metadata(self, plaintext, enc_data):
        padlength = padding_length(len(plaintext))
        digest = enc_data[0:self.digest_size]
        iv = enc_data[self.digest_size:self.digest_size+self.iv_size]
        m_data = {
            'digest': digest,
            'iv': iv,
            'padding': enc_data[(-1 * padlength):],
            'pad_len': padlength,
            'length': len(bytes(plaintext))
        }
        return m_data

    def decrypt_data(self, data, metadata):
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
            data = self.decrypt_data(data, metadata)
        else:
            print("no data read")

        return data[offset:(offset + length)]

    def write_file(self, path, buf, offset, metadata):
        print(metadata)
        #compute the entire plaintext to be written to the file
        #currently does not support writing less than the entire file
        plaintext = buf
        buf_len = len(buf)
        data_len = metadata['length']
        old_len = metadata['old_length']
        try:
            with open(path, 'r') as f:
                data = f.read()
                if len(data) > 0:
                    print("Load previous data len: %s " % len(data))

                    # Check for seek ahead
                    # if  offset > old_len + buf_len and metadata['truncated']:
                    #     #print_bytes(data)
                    #     print("Seeking ahead - prev: %s offset: %s len: %s" % (old_len, offset, buf_len))
                        
                    #     if is_all_zero(data): #is_empty_meta(metadata)
                    #         print("skip decrypt on empty seek")
                    #     else:
                    #         # Decrypt partial data if needed
                    #         prev_enc_data = data[0:old_len]
                    #         prev_data = self.decrypt_data(prev_enc_data, metadata)
                    #         #print_bytes(prev_enc_data)
                    #         #print_bytes(prev_data)

                    #         data = prev_data + data[old_len:offset]
                    # else:
                        # Decrypt all data
                    print("Decrypt all data")
                    data = self.decrypt_data(data, metadata)

                #print_bytes(data)
                plaintext = data[:offset] + buf + data[(offset + len(buf)):]

        except IOError:
            plaintext = buf

        #print_bytes(plaintext)
        
        #encrypt and write the metadata file
        enc_block = self.encrypt_data(plaintext)
        enc_data = enc_block[0]
        new_meta = enc_block[1]

        #write the actual file. The first 80 bytes of filedata are the 
        #hex digest + the iv. The last "padlength" bytes are block padding
        write_data = enc_data[self.metadata_header_length:(-1*new_meta['pad_len'])]
        with open(path, 'wb') as f:
            f.write(write_data)

        bytes_written = len(write_data)
        sze = min(len(buf), bytes_written)

        #print(metadata)
        return (sze, new_meta)
