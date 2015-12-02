
def is_all_zero(data):
    z_map = map(lambda a: a == chr(0), data)
    r = reduce(lambda a,b: a & b, z_map)
    return r

def print_bytes(data):
    print(' '.join(format(x, '02x') for x in bytearray(data)))
