from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from pbkdf2 import PBKDF2
from os import urandom

def encrypt(content, encryption_key, signing_key):
    iv = urandom(16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    encrypted = '%s%s' % ( iv, cipher.encrypt(pad(content)) )
    hash = HMAC.new(signing_key, digestmod=SHA256)
    hash.update(encrypted)
    return '%s%s' % (hash.hexdigest(), encrypted)

def decrypt(content, encryption_key, signing_key):
    signature, contents = ( content[:64], content[64:] )
    hash = HMAC.new(signing_key, digestmod=SHA256)
    hash.update(contents)
    if signature != hash.hexdigest():
        raise Exception('Invalid Signature')
    iv, contents = ( contents[:16], contents[16:] )
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(contents))

BS = 16

# added for use with enc_fs
def padding_length(plaintext_length):
    return BS - plaintext_length % BS

pad = lambda s: s + (padding_length(len(s))) * chr(padding_length(len(s))) 
unpad = lambda s : s[0:-ord(s[-1])]

def make_key(password): # makes a 256-bit key, a 128-bit iv and a 64-bit password salt
  iv = urandom(16) # 128-bit
  salt = urandom(8) # 64-bit
  key = urandom(32) # 256-bit key
  cipher = AES.new(PBKDF2(password, salt).read(32), AES.MODE_CBC, iv)
  print('Generated Key: %s' % b64encode(key))
  return '%s%s%s' % (salt, iv, cipher.encrypt(pad(key)))

def get_key(password, key_matter):
    salt = key_matter[:8]
    iv = key_matter[8:24]
    key = key_matter[24:]
    cipher = AES.new(PBKDF2(password, salt).read(32), AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(key))
