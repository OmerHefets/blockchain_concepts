import keys_address as ka

# checking the "63 length" private key error
# if it's since the first bit is 0, then the freq should be 1/16


def freq_63_check(iter):
    len_63 = 0
    len_64 = 0
    for i in range(iter):
        len_priv_key = len(ka.generate_private_key())
        if len_priv_key == 64:
            len_64 += 1
        elif len_priv_key == 63:
            len_63 += 1
    print("# of 64 length keys: {}".format(len_64))
    print("# of 63 length keys: {}".format(len_63))
    print("len63 / len64 ratio is: {}".format(len_63 / len_64))


freq_63_check(10000)