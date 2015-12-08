
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

def printhex(bytestr):
    print(':'.join(x.encode('hex') for x in bytestr))

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

    def encrypt(self, text):
        if len(text) % self.encryption_function.block_size == 0:
            return self.cipher.encrypt(text)
        else:
            paddedtext = pad(text)
            return self.cipher.encrypt(paddedtext)

    def decrypt(self, text):
        #could assert block size here
        return unpad(self.cipher.decrypt(text))


#more test vectors need to be written (can be found on the internet), but I don't have time at the moment

key = '\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06'
iv = '\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41'
plaintext = 'Single block msg'
expected_enc = '\xe3\x53\x77\x9c\x10\x79\xae\xb8\x27\x08\x94\x2d\xbe\x77\x18\x1a'

c = Cipher(CipherType.AES_128(), BlockMode.MODE_CBC, key, iv)
enc = c.encrypt(plaintext)

assert expected_enc == enc[0:16]
printhex(enc)






