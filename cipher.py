
from Crypto.Cipher import AES
from Crypto import Random

#DELETE ME. we don't have our own implementations. we're calling libraries
#class BlockMode:

#    def __init__(self, is_fluid):
 
        #is_fluid = True means passing text where len(text) % blocklength != 0
        #will not pass the last block to text to be encrypted until more data is passed
#        self.is_fluid = is_fluid

#    def seed(self, iv_size):
#        self.iv = rand(iv_size) #ugh, fix this to be more random and have variable length


#DELETE ME. we don't have our own implementations. we're calling libraries
#class CBCMode(BlockMode):

#    def __init__(self, cipher, is_fluid):
#        super(BlockMode, self).__init__(is_fluid)
#        self.seed(cipher.block_size)

#    def encrypt(text):
#       if is_fluid:
#       else:
#           current_offset = 0
#           next_offset = cipher.block_size
#           block = text[current_offset:next_offset]

#           while len(block) > 0:
#               if len(block) == cipher.blocksize:
#                   plaintext = block xor text

class BlockMode:

    MODE_ECB = 1
    MODE_CBC = 2
    MODE_CTR = 3


#key and block sizes are in bytes
#assumes a byte size of 8 bits
class CipherType:

    def __init__(self, name, key_size, block_size):
        self.name = name
        self.key_size = key_size
        self.block_size = block_size

    @staticmethod
    def AES_128():
        return CipherType('AES-128', 16, 16)

    @staticmethod
    def AES_192():
        return CipherType('AES-192', 24, 16)

    @staticmethod
    def AES_256():
        return CipherType('AES-256', 32, 16)
    

#just write encrypt_stream(stream, offset) now
#maybe in a completely different class
#actually, maybe even in enc_fs.
#eh. probably in enc_fs. i don't know. 

class Cipher:

    def __init__(self, encryption_function, block_mode, key, iv = None):

        assert encryption_function.key_size == len(key)
        self.encryption_function = encryption_function

        if iv is None:
            iv = generate_iv(encryption_function.block_size)

        #i know. shoot me. they're all the same. i'll fix it before it goes to master.
        if encryption_function.name == 'AES-128':
            internal_mode = self.map_aes_block_mode(block_mode)
            self.cipher = AES.new(key, internal_mode, iv)

        elif encryption_function.name == 'AES-192':
            internal_mode = self.map_aes_block_mode(block_mode)
            self.cipher = AES.new(key, internal_mode, iv)

        elif encryption_function.name == 'AES-256':
            internal_mode = self.map_aes_block_mode(block_mode)
            self.cipher = AES.new(key, internal_mode, iv)

    def map_aes_block_mode(self, mode):
        if mode == BlockMode.MODE_CBC:
            return AES.MODE_CBC
        elif mode == BlockMode.MODE_ECB:
            return AES.MODE_ECB
        elif mode == BlockMode.MODE_CTR:
            return AES.MODE_CTR

        return 0 #need to throw an unsupportedexception here. 

    def generate_iv(self, block_size):
        return rand(block_size)

    #we should switch to a streaming mode, ciphertext stealing, or residual block termination
    def encrypt(self, text):
        paddedtext = self.pad(text)
        return self.cipher.encrypt(paddedtext)

    #see the comment on encrypt()
    def decrypt(self, text):
        #could assert block size here
        return self.unpad(self.cipher.decrypt(text))

    def get_pad_length(self, s):
        return self.encryption_function.block_size - len(s) % self.encryption_function.block_size

    def pad(self, s): 
        pad_length = self.get_pad_length(s)
        return s + (pad_length * chr(pad_length))

    def unpad(self, s, blocksize):
        return s[0:-ord(s[-1])]

