# https://github.com/ahmedfgad/ArithmeticEncodingPython
import pyae
from decimal import getcontext

# Example for encoding a simple text message using the PyAE module.

# Create the frequency table.

letters = {
    "e":  12.49,
    "t":   9.28,
    "a":   8.04,
    "o":   7.64,
    "i":   7.57,
    "n":   7.23,
    "s":   6.51,
    "r":   6.28,
    "h":   5.05,
    "l":   4.07,
    "d":   3.82,
    "c":   3.34,
    "u":   2.73,
    "m":   2.51,
    "f":   2.40,
    "p":   2.14,
    "g":   1.87,
    "w":   1.68,
    "y":   1.66,
    "b":   1.48,
    "v":   1.05,
    "k":   0.54,
    "x":   0.23,
    "j":   0.16,
    "q":   0.12,
    "z":   0.09, }

extras = {
    # "0":   1,
    # "1":   1,
    # "2":   0.5,
    # "3":   0.5,
    # "4":   0.5,
    # "5":   0.5,
    # "6":   0.5,
    # "7":   0.5,
    # "8":   0.5,
    # "9":   0.5,
    " ": 29,
    ",":  1,
    ".":  0.5,
    # "'":  0.5,
    # "-":  0.5,
}

frequency_table = {**letters, **extras}

# Create an instance of the ArithmeticEncoding class.
AE = pyae.ArithmeticEncoding(frequency_table,
                             save_stages=False)

# Default precision is 28. Change it to do arithmetic operations with larger/smaller numbers.
getcontext().prec = 1000

# original_msg = "bdab"
# original_msg = "eeeeeeeeee"
original_msg = "e"
# original_msg = "hello"
# original_msg = "hello, welcome to the matrix"
original_msg = "hello, welcome to the matrix. please take a seat and the cheshire cat will be right with you."
# original_msg = "hi welcome to the matrix plz take a seat n the cheshire cat will be right with you"
# original_msg = "hi welkm to matrix plz tek seat n cheshire cat ll b right wit u"
# original_msg = "i ate falafel for dinner tonight"
# original_msg = "meet me at 3pm at park"
original_msg = "meet me at three at park"
# original_msg = "turn left"

# original_msg = "Genode as virtualization layer for Qubes OS. \
# Qubes OS is a desktop operating system that follows the principle of security through compartmentalization. \
# In spirit, it is closely related to Genode.".lower()

print("Original Message: {msg}".format(msg=original_msg))
for bpc in [4.5, 4.0, 3.5]:
    print("strlen={strlen} * {bpc} bits per char ~= est. {strbits} bits in string".format(
        strlen=len(original_msg),
        bpc=bpc,
        strbits=bpc*len(original_msg)) )


# Encode the message
encoded_msg, encoder , interval_min_value, interval_max_value = AE.encode(msg=original_msg,
                                                                          probability_table=AE.probability_table)
print("Encoded Message: {msg}".format(msg=encoded_msg))

# Get the binary code out of the floating-point value
binary_code, encoder_binary = AE.encode_binary(float_interval_min=interval_min_value,
                                               float_interval_max=interval_max_value)
print("The binary code is: {binary_code}".format(binary_code=binary_code))
print("info bits in binary code:", len(binary_code)-2)
print("purebits", binary_code[2:])

print("compression ratio:", (len(binary_code)-2) / (8*len(original_msg)) )

# Decode the message
msglen = len(original_msg)
print("msglen:", msglen)
# decoded_msg, decoder = AE.decode(encoded_msg=encoded_msg,
decoded_msg, decoder = AE.decode(encoded_msg=pyae.bin2float(binary_code),
                                 msg_length=msglen,
                                 probability_table=AE.probability_table)
# print("Decoded Message: {msg}".format(msg=decoded_msg))

decoded_msg = "".join(decoded_msg)
print(decoded_msg)

print("Message Decoded Successfully? {result}".format(result=original_msg == decoded_msg))

def try_len_guess():
    print("TRYING DECODING WITH LENGTH GUESSING")

    starting_guess = int((len(binary_code)-2) / 4)
    print("starting guess", starting_guess)

    for distance in range(0,10):
        low = starting_guess - distance
        high = starting_guess + distance

        msglen = low
        decoded_msg, decoder = AE.decode(encoded_msg=encoded_msg,
                                         msg_length=msglen,
                                         probability_table=AE.probability_table)
        decoded_msg = "".join(decoded_msg)
        print("{startg} -{dst} = {length}:".format(dst=distance,
                                                startg=starting_guess,
                                                length=msglen), decoded_msg)

        msglen = high
        decoded_msg, decoder = AE.decode(encoded_msg=encoded_msg,
                                         msg_length=msglen,
                                         probability_table=AE.probability_table)
        decoded_msg = "".join(decoded_msg)
        print("{startg} +{dst} = {length}:".format(dst=distance,
                                                startg=starting_guess,
                                                length=msglen), decoded_msg)

def try_subtract_len():
    binary_len = int( bin(len(original_msg)) , 2)
    print("bin len", repr(binary_len))

    trunc = binary_code[2:] # get just the fractional part of the string
    print("trunc", repr(trunc))
    bin_code_truncated = int("0b"+trunc, 2) # turn that fraction string into its own integer
    print("bin code trunc", repr(bin_code_truncated))

    sub = bin_code_truncated - binary_len
    print("bin code sub  ", repr(sub))
    print("bianry_code as bin2float", pyae.bin2float(binary_code))

    msg_len = binary_len
    for lngth in range(msg_len-5, msg_len+5):
        print("\nTRYING LENGTH WITH LENGTH:", lngth)
        # Decode the message
        msglen = lngth
        print("msglen:", msglen)
        guess_int = sub + lngth # reconcstuct bin_code_truncated, (as int)
        print(guess_int)

        # reconstruct fractional part of string ("trunc")
        trunc2 = '0'+bin(guess_int)[2:]
        print("trunc2", repr(trunc2))
        # assert trunc == trunc2

        bin_code_reconstructed = "0."+trunc2

        decoded_msg, decoder = AE.decode(encoded_msg=pyae.bin2float(bin_code_reconstructed),
                                         msg_length=msglen,
                                         probability_table=AE.probability_table)
        # print("Decoded Message: {msg}".format(msg=decoded_msg))

        decoded_msg = "".join(decoded_msg)
        print("decoded_msg", decoded_msg)


from hashlib import sha256  # for the passphrase
import base64, pyffx
import sys
from loguru import logger
loglvl = "ERROR"
# loglvl = "INFO"
# loglvl = "DEBUG"

logger.remove()
logger.add(sys.stderr, level=loglvl, backtrace=True, diagnose=True)

# For pyffx.
BIN_ALPHABET = "01"
HEX_ALPHABET = "0123456789ABCDEF="  # Base16 hexadecimal.
B32_ALPHABET = "234567ABCDEFGHIJKLMNOPQRSTUVWXYZ="
FFX_ALPHABET = BIN_ALPHABET
# CHARBASE = len(FFX_ALPHABET) - 1  # hex=16, b32=32, etc...
CHARBASE = len(FFX_ALPHABET)   # idk why the others have extra '=' symbol

def passwd2key(passwd):
    passphrase = str(passwd)
    key = sha256(passphrase.encode()).hexdigest().encode()
    return key

def encrypt(passwd, msg):
    key = passwd2key(passwd)
    encoded = compressed  = msg

    logger.info("encoded:   " + repr(encoded))

    esay = pyffx.String(key, alphabet=FFX_ALPHABET, length=len(encoded))
    encrypted = esay.encrypt(encoded)

    chars_ = len(encrypted)
    bits_ = len(encrypted) * (CHARBASE / 2)

    logger.info("encrypted: {} ({} chars, {} bits)", repr(encrypted), chars_, bits_)
    return encrypted

def decrypt(passwd, msg):
    key = passwd2key(passwd)
    fec_decoded = msg

    logger.info("ciphertxt: {}", repr(fec_decoded))

    logger.debug("{}, {}", repr(key), repr(FFX_ALPHABET)) # WARNING: SECURITY RISK
    ehear = pyffx.String(key, alphabet=FFX_ALPHABET, length=len(fec_decoded))
    decrypted = ehear.decrypt(fec_decoded)
    logger.info("decrypted: {}", repr(decrypted))

    decoded = decrypted
    logger.info("decoded:  " + repr(decoded))
    return decoded

def bincode2purebits(_bin_code):
    trunc = _bin_code[2:] # get just the fractional part of the string
    logger.debug("trunc {}", repr(trunc))
    return trunc

def purebits2bincode(_pure_bits):
    logger.info("recv purebits: {}", _pure_bits)
    _bin_code_reconstructed = "0."+_pure_bits
    return _bin_code_reconstructed

def try_crypt():
    # get the truncated purebits to prepare it for encryption
    trunc = bincode2purebits(binary_code)
    logger.debug("trunc: {}", repr(trunc))

    # encrypt the trunc-purebits to the length of orig msg
    msg_len = len(original_msg)
    _crypted = encrypt(msg_len, trunc)
    logger.info("crrypted: {}", _crypted)


    for lngth in range(msg_len-3, 1+msg_len+3):
        # print("\nTRYING WITH LENGTH:", lngth)

        msglen = lngth
        # print("msglen:", msglen)

        # do decryption here
        _decrypted = decrypt(msglen, _crypted)
        logger.info("decrpted: {}", _decrypted)

        # restore original binary code now
        bin_code_reconstructed = purebits2bincode(_decrypted)

        decoded_msg, decoder = AE.decode(encoded_msg=pyae.bin2float(bin_code_reconstructed),
                                         msg_length=msglen,
                                         probability_table=AE.probability_table)
        # print("Decoded Message: {msg}".format(msg=decoded_msg))

        decoded_msg = "".join(decoded_msg)
        print("Tried with length {}, decoded_msg: {}".format(lngth, decoded_msg))

def do_noncrypto_decoding_at_len(msglen):
    decoded_msg, decoder = AE.decode(encoded_msg=encoded_msg,
                                         msg_length=msglen,
                                         probability_table=AE.probability_table)
    decoded_msg = "".join(decoded_msg)
    return decoded_msg

def do_decoding_at_len(msglen, _crypted):
    # do decryption here
    _decrypted = decrypt(msglen, _crypted)
    logger.info("decrpted: {}", _decrypted)

    # restore original binary code now
    bin_code_reconstructed = purebits2bincode(_decrypted)

    decoded_msg, decoder = AE.decode(encoded_msg=pyae.bin2float(bin_code_reconstructed),
                                     msg_length=msglen,
                                     probability_table=AE.probability_table)
    # print("Decoded Message: {msg}".format(msg=decoded_msg))

    decoded_msg = "".join(decoded_msg)
    return decoded_msg

def try_crypt_guess():
    # First, encode and encrypt it...

    # get the truncated purebits to prepare it for encryption
    trunc = bincode2purebits(binary_code)
    logger.debug("trunc: {}", repr(trunc))

    # encrypt the trunc-purebits to the length of orig msg
    msg_len = len(original_msg)
    _crypted = encrypt(msg_len, trunc)
    logger.info("crrypted: {}", _crypted)

    crypted_msg = _crypted

    # Ok. Now try to get it back...

    purebits_len = len(crypted_msg)
    logger.info("purebits_len: {}", purebits_len)
    starting_guess = int(purebits_len / 4)
    print("starting guess", starting_guess)

    print("{startg}    = {startg}:".format(startg=starting_guess),
          repr(do_decoding_at_len(starting_guess, crypted_msg))
    )

    for distance in range(1,1+5000):
        low = starting_guess - distance
        high = starting_guess + distance

        # We can ignore negative msg lengths, and msg length 0
        if low >= 1:
            print("{startg} -{dst} = {length}:".format(dst=distance,
                                                       startg=starting_guess,
                                                       length=low),
                  repr(do_decoding_at_len(low, crypted_msg)) )

        # If the
        if high <= purebits_len:
            print("{startg} +{dst} = {length}:".format(dst=distance,
                                                       startg=starting_guess,
                                                       length=high),
                  repr(do_decoding_at_len(high, crypted_msg)) )


# crypted = encrypt(32, "000000000000000000000000")
# decrypt(32, crypted)

# try_len_guess()
# try_subtract_len()
# try_crypt()
try_crypt_guess()
