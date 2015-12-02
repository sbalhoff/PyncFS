
# Metadata

def is_empty_meta(metadata):
    empty = False
    if 'empty' in metadata:
        empty = metadata['empty']
    print("empty: %s" % empty)
    return empty

# Misc

def is_all_zero(data):
    z_map = map(lambda a: a == chr(0), data)
    r = reduce(lambda a,b: a & b, z_map)
    return r

def merge_dict(a, b):
	return dict(a.items() + b.items())

# Debug

def print_bytes(data):
    print(' '.join(format(x, '02x') for x in bytearray(data)))

