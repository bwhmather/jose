def pad_pkcs7(s, block_size):
    padding = block_size - (len(s) % block_size)
    # TODO would be cleaner to do `bytes(sz) * sz` but python 2 behaves
    # strangely
    return s + (chr(padding) * padding).encode('ascii')


def unpad_pkcs7(s):
    try:
        return s[:-ord(s[-1])]
    # Python 3 compatibility
    except TypeError:
        return s[:-s[-1]]


def const_compare(stra, strb):
    if len(stra) != len(strb):
        return False

    try:
        # python 2 compatibility
        orda, ordb = list(map(ord, stra)), list(map(ord, strb))
    except TypeError:
        orda, ordb = stra, strb

    res = 0
    for a, b in zip(orda, ordb):
        res |= a ^ b
    return res == 0
