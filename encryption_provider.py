from encryptionstore import retrieve_key
from encryption import encrypt, decrypt, padding_length
import os
import hashlib

enc_keymatter_file = '.enc_keymatter'
sign_keymatter_file = '.sign_keymatter'

encryption_password = ''
signing_password = ''

class BasicEncryption():
    def __init__(self, fs, enc_pass, sign_pass):
        global enc_keymatter_file
        global sign_keymatter_file

        self.fs = fs
        self.encryption_key = retrieve_key(enc_pass, self.fs._full_path(enc_keymatter_file))
        self.signing_key = retrieve_key(sign_pass, self.fs._full_path(sign_keymatter_file))
        self.metadata_header_length = 80

    def _metadata_filename(self, partial):
        return '.' + hashlib.md5(partial).hexdigest()

    def _metadata_file(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]

        #has a race condition, but good enough for now
        metadatadir = os.path.join(self.fs.root, 'metadata')
        if not os.path.exists(metadatadir):
            os.makedirs(metadatadir)

        return os.path.join(metadatadir, self._metadata_filename(partial))

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

    def is_metadata_file(self, partial):
        return partial.split('/')[0] == 'metadata'

    def is_key_file(self, partial):
        return partial == enc_keymatter_file or partial == sign_keymatter_file

    def is_blacklisted_file(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]

        return self.is_key_file(partial) or self.is_metadata_file(partial)

    #blocklength needs to be moved out of this function
    #do not need to read from offset 0 either
    #also need to check whether to append the metadata
    def read(self, path, length, offset, fh):
        blocklength = 16 #fix this

        os.lseek(fh, 0, os.SEEK_SET)

        readlength = offset + length
        if readlength % blocklength != 0:
            readlength = readlength + blocklength - readlength % blocklength

        data = os.read(fh, readlength)
        if len(data) > 0:
            data = self.decrypt_with_metadata(path, data)
        return data[offset:(offset + length)]

    def write(self, path, buf, offset, fh):
        fullpath = self.fs._full_path(path)
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
