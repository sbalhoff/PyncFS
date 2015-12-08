from cipher import CipherType, Cipher, BlockMode

#more test vectors need to be written (can be found on the internet), but I don't have time at the moment
#https://tools.ietf.org/html/rfc3602 has some test vectors.

def printhex(bytestr):
    print(':'.join(x.encode('hex') for x in bytestr))

encryption_tests = [

{
    'cipher' : CipherType.AES_128(),
    'block_mode' : BlockMode.MODE_CBC,
    'key' : '\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06',
    'iv' : '\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41',
    'plaintext' : 'Single block msg',
    'expected_ciphertext' : '\xe3\x53\x77\x9c\x10\x79\xae\xb8\x27\x08\x94\x2d\xbe\x77\x18\x1a'
},

{
    'cipher' : CipherType.AES_128(),
    'block_mode' : BlockMode.MODE_CBC,
    'key' : '\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a',
    'iv' : '\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58',
    'plaintext' : ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                   "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"),
    'expected_ciphertext' : ("\xd2\x96\xcd\x94\xc2\xcc\xcf\x8a\x3a\x86\x30\x28\xb5\xe1\xdc\x0a"
                             "\x75\x86\x60\x2d\x25\x3c\xff\xf9\x1b\x82\x66\xbe\xa6\xd6\x1a\xb1")
}

]

for test in encryption_tests:
    cipher = Cipher(test['cipher'], test['block_mode'], test['key'], test['iv'])
    ciphertext = cipher.encrypt(test['plaintext'])
    assert test['expected_ciphertext'] == ciphertext[0:len(test['plaintext'])]
    printhex(ciphertext)
