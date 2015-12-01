import sys
sys.path.append('../dcc')

from encryption import make_key, get_key

import os

def retrieve_key(password, path):
    keymatter = ''

    try:
        f = open(path, 'r')
        keymatter = f.read()
        f.close()
    except IOError:
        keymatter = make_key(password)
        f = open(path, 'w')
        f.write(keymatter)
        f.close()
        
    return get_key(password, keymatter)


#print(retrieve_key('password', '/home/stephen/Documents/keymatter'))
