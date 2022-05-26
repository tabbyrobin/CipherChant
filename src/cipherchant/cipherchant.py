#!/usr/bin/env python3
"""CipherChant, send short messages encrypted, but human-friendly format."""
#################################################
# to get dependencies: poetry install

# or manually: pip install --user pyffx hashlib zfec asyncio trio tricycle fire click
# (Should be most of them)

# note: pyunishox -- poetry will install it from repo. Download will
# take a minute.

# problem: bananaphone -- python2. Need to manually fetch (git clone
# and pip2 install)


## Adjustables for debugging ##

COMPRESSION_ON = True
# COMPRESSION_ON = False

FEC_ON = True
FEC_ON = False

loglvl = "DEBUG"

#################

import math
import sys
from importlib import resources

from loguru import logger

logger.remove()
logger.add(sys.stderr, level=loglvl, backtrace=True, diagnose=True)

import base64  # pre-encode for pyffx
import glob  # zfec wrapping
import os  # zfec wrapping
import shutil  # zfec wrapping
import subprocess  # for bananaphone
import tempfile  # zfec wrapping
import time
from asyncio.subprocess import PIPE  # for bananaphone
from hashlib import sha256  # for the passphrase

import asyncclick as click
import fire  # fire, click for UI
import pyffx  # encrypt
import pyunishox as ushx  # compress
import tricycle
import trio  # trio for bananaphone
import zfec.filefec as fec  # erasure code

###########################

# For pyffx.
HEX_ALPHABET = "0123456789ABCDEF="  # Base16 hexadecimal.
B32_ALPHABET = "234567ABCDEFGHIJKLMNOPQRSTUVWXYZ="
FFX_ALPHABET = HEX_ALPHABET

CHARBASE = len(FFX_ALPHABET) - 1  # hex=16, b32=32, etc...

# For zfec
REDUNDANCY = 1 / 1  # no redundancy
REDUNDANCY = 4 / 5

BANANA_SPLIT_CHAR = "-"
CIPHERCHANT_SPLIT_CHAR = " "

BP_WRAPPER_PATH = resources.path("cipherchant.data", "bp_wrapper.py")
# BP_WRAPPER_PATH =  resources.path('cipherchant', 'data/bp_wrapper.py')

##########################################
# 9 bit (7776 words)
BANANA_DICT_PATH = "eff_large_wordlist.txt"

# takes 30s to load
BANANA_DICT_PATH = "american-english.2345689.txt"  # 18 bit @ sha256 or sha1

# good default dictionary for testing
BANANA_DICT_PATH = "american-english"  # 13 bit (102401 words)

BANANA_DICT_PATH = resources.path("cipherchant.data", BANANA_DICT_PATH)

# sudo ln -s ~/ProjectCipherChant/cipherchant/src/cipherchant/data/american-english /usr/share/dict/words
##########################################

BANANA_BPW = 13
# BANANA_BPW = 18

# Generally we want sha1 cuz its the fastest. Sometimes sha256 can get
# us an extra bpw on a dictionary.
# https://automationrhapsody.com/md5-sha-1-sha-256-sha-512-speed-performance/
BANANA_HASH = "sha1"
################################################################################

# fmt: off
def   compress(var): return ushx.compress  ( bytes(var, 'utf-8') )
def decompress(var): return ushx.decompress( bytes(var) )
# fmt: on


class CipherChant:
    """Basic CLI/pulling it all together class.

    STEPS:       compress hex crypto fec banana.
    REVERSE STEPS: banana fec crypto hex compress.

    TBD: Make Echant and Disenchant wholely separate classes. These are
    basically UI components, not part of the core logic. The only thing
    they share is the key, which doesn't necessarily have the same
    value. (could have different sendkey vs receive key; or send/receive
    with several different people).

    They can inherit their key-retrieving logic from a CipherChant parent
    class.

    """

    def __init__(self, p=None):
        logger.debug("")
        self.p = p

        # CLI alias shortcuts
        self.e = self.enchant
        self.d = self.disenchant

    def enchant(self, m):
        logger.debug("enter")
        retval = trio.run(self._enchant, m)
        logger.debug("returning")
        return retval # this has side effect of printing to stdout. Is
        # this because of Fire?


    def disenchant(self, c):
        logger.debug("")
        retval = trio.run(self._disenchant, c)
        logger.debug("returning")
        return retval

    # @click.command()
    @logger.catch
    async def _enchant(self, message=None):
        logger.debug("enter")
        self.message = message

        # (1) Do asynchronously:
        #  (1a) collect the encoder object
        #  (1b) collect the key and message
        # (2) encode the msg to the key using the encoder

        # Boot the encoder up in the background, to give it as much of
        # an edge on boot time as possible. Booting the encoder can
        # take as much as 30 seconds on a large corpus (3mil tokens;
        # in a VM on a laptop). In the meantime, user can compose
        # their message.

        async with trio.open_nursery() as nursery:
            nursery.start_soon(self._set_bp_encoder)
            nursery.start_soon(self._get_key_and_msg)

        chant = await say(self.message, self.key, self.BPEnc)

        # print ('******************', file=sys.stderr)
        # print ('Enchanted message: ', chant, file=sys.stderr, )
        # # sys.stderr.flush()
        # print ('******************', file=sys.stderr)

        # print(chant)
        logger.debug("returning")
        return chant # added for pytest

    async def _get_key_and_msg(self):
        await self._get_key()
        if self.message is None:
            # if not sys.stdin.isatty():
            # message = click.get_text_stream('stdin')
            # else:
            message = click.prompt("Enter message to encrypt")
            self.message = message

    @logger.catch
    async def _disenchant(self, chant=None):
        logger.debug("")
        self.chant = chant # pytest

        await self._get_key()

        # if chant is None:
        if self.chant is None: # pytest
            chant = click.prompt("Enter chant to decrypt")
            self.chant = chant  # pytest
        # message = hear(chant, self.key).decode()
        message = hear(self.chant, self.key).decode()  #pytest
        # print( '*********************' , file=sys.stderr)
        # print( 'Disenchanted message:', file=sys.stderr)
        # print( '*********************' , file=sys.stderr)
        print(message)
        logger.debug("returning")
        return message  # added for pytest

    async def _get_key(self):
        logger.debug("enter")
        # BUG: with this setup, if we pipe but do not specify -p
        # PASSPHRASE_FILE, then click.prompt() will eat up our
        # chant/message as passphrase
        pfilepath = self.p
        # But, this setup works if we always specify -p, OR if we dont pipe
        if pfilepath is not None:
            pfd = click.open_file(pfilepath)
            passphrase = pfd.readline()
        elif pfilepath is None:
            passphrase = click.prompt("Enter passphrase for encryption", err=True)

        self.key = sha256(passphrase.encode()).hexdigest().encode()
        logger.debug('end')

    async def _set_bp_encoder(self):
        logger.debug("enter")
        self.BPEnc = await CipherChant._get_bp_encoder()
        logger.debug("exit")

    # @classmethod
    @staticmethod
    async def _get_bp_encoder():
        """this function mostly just stores data to pass to
        load_bp_encoder. Maybe this data should be class attributes instead.

        This func also does a little bit of logic around timeouts and error
        catching. Maybe this could go in the init func of its own class?

        """
        logger.debug("")

        with BP_WRAPPER_PATH as bp_wrapper, BANANA_DICT_PATH as dict_path:

            hashfun = BANANA_HASH
            bpw = BANANA_BPW
            model = "random"
            # model = 'markov' # NOTE: random uses much less RAM than markov.

            # for sarge
            dict_path = str(dict_path)
            bp_wrapper = str(bp_wrapper)

            banana_encode_cmd = [
                "python2",
                # BP_WRAPPER_PATH,
                bp_wrapper,
                "Encoder",
                "--encoding_spec",
                "words,%s,%s" % (hashfun, bpw),
                "--model",
                model,
                "--corpus",
                dict_path,
            ]

            TIMEOUT = 35  # currently our largest wordlist (3mil) takes ~31s
            with trio.move_on_after(TIMEOUT) as cancel_scope:
                b_enc = await load_bp_encoder(banana_encode_cmd)

            if cancel_scope.cancelled_caught:
                print("TIMED OUT WHILE LOADING ENCODER")
                # this shuts down the whole python interpreter process?
                # ensures the encoder processes are reaped. Better way to do
                # this?
                sys.exit(1)

        # self.BPEnc = b_enc
        logger.debug("exiting function")
        return b_enc


class BananaEncoder:
    """So we can:
    b_enc = BananaEncoder() #boot it up in bg
    ...do some other stuff...
    encoded = b_enc.encode(data)
    encoded_ = b_enc.encode(more_data)"""

    def __init__(
        self, encoding_spec=("words", "sha1", "13"), model="random", corpus="/usr/share/dict/words"
    ):
        self.is_ready = False

        w, h, b = encoding_spec
        encoding_spec = "%s,%s,%s" % (w, h, b)

    def encode(self, data):
        pass

    # async def [CipherChant.]_get_bp_encoder(self):
    # async def load_bp_encoder(banana_encode_cmd):
    # async def banana_encode(list_of_stuff, bp_encoder_instance):

'''
    BananaEncoder._load(banana_encode_cmd)

    BananaEncoder.encode_list(list_of_stuff)
    BananaEncoder.encode(data)
    BananaEncoder.encode_list_or_singleton(stuff)
'''
class CLI:
    pass


class Seance:
    pass


class Questioner:
    pass


async def load_bp_encoder(banana_encode_cmd):
    logger.debug("")
    logger.info("calling up bananaphone in trio... {}", banana_encode_cmd)

    import sarge

    feeder = sarge.Feeder()

    b_enc = sarge.run(
        banana_encode_cmd,
        stdout=sarge.Capture(buffer_size=1),
        stderr=sarge.Capture(buffer_size=1),
        input=feeder,
        async_=True,
    )

    # b_enc = await trio.open_process(
    #     banana_encode_cmd,
    #     stdout=PIPE,
    #     stderr=PIPE,
    #     stdin=PIPE,
    # )

    # check if the encoder is loaded and ready to receive chunks

    output = b""
    while True:  # this should timeout at some point TBD

        # moreoutput = await b_enc.stderr.receive_some()
        moreoutput = b_enc.stderr.readline()
        output += moreoutput
        logger.debug("waiting on encoder...")
        logger.debug("total stderr from wrapper so far: " + repr(output))

        b_READY = bytes("READY", "utf-8")
        b_txt_encode = bytes("text to encode", "utf-8")
        if b_READY and b_txt_encode in output:

            logger.info("FOUND ENCODER READY!")
            # await b_enc.stderr.aclose()
            # time.sleep(1)
            break

        await trio.sleep(1.0)

    logger.debug("")
    # return b_enc
    return b_enc, feeder


async def banana_encode(list_of_stuff, bp_encoder_instance):
    logger.debug("")
    fec_encoded = list_of_stuff

    # Bananaphone Encoding is much more intensive than
    # decoding. Encoding uses a dictionary, decoding does not. As
    # such, we use a wrapper so that we can boot bananaphone encoder
    # up just once, and send data at it several times.

    # We also make the encoder async.

    # b_enc = bp_encoder_instance
    b_enc, feeder = bp_encoder_instance

    banana_chunks = []
    for chunk in fec_encoded:
        # When feeding to Bananaphone our code wants bytes, not
        # strings. If FEC is on, it will be feeding us bytes, so no
        # conversion necessary. If FEC is off, then we will have a
        # string, which we need to convert to bytes before feeding to
        # banana encoder.
        if type(chunk) is not bytes:
            chunk = chunk.encode()

        logger.debug("sending this toward bp_wrapper: " + repr(chunk))
        # await b_enc.stdin.wait_send_all_might_not_block()
        # await b_enc.stdin.send_all(chunk)
        feeder.feed(chunk)

        await trio.sleep(0.5)

        # we have to send bp_wrapper a newline so it knows to send it
        # on to bananaphone (bp wrapper expects: <text> RET)
        logger.debug("sending bp wrapper a newline")
        # await b_enc.stdin.wait_send_all_might_not_block()
        # await b_enc.stdin.send_all(b"\n")
        feeder.feed(b"\n")

        # banana_chunk = await tricycle.TextReceiveStream(
        #     b_enc.stdout,
        #     encoding="utf-8",
        # ).receive_line()

        # banana_chunk = bytes(banana_chunk, "utf-8")  # for tricycle

        # b_enc.stdout.expect('\n')
        banana_chunk = b_enc.stdout.readline()

        # banana_chunk = b''
        # while True:
        #     time.sleep(0.5)

        #     received =  await b_enc.stdout.receive_some()
        #     print('piece received from bp wrapper= ', repr(received))

        #     banana_chunk += received

        #     if received == bytes('', 'utf-8'):
        #         break

        #     sentinel = bytes('\n', 'utf-8')
        #     if received.endswith(sentinel):
        #         #print('found a NEWLINE')
        #         break

        logger.debug("TOTAL received from bp wrapper: " + repr(banana_chunk))

        # our wrapper bp_wrapper.py adds a \n to signal end of
        # transmission. we take it off.
        banana_chunk = banana_chunk.strip(b"\n")

        banana_chunks.append(banana_chunk)

    # banana end: banana returns banana_chunks (list)
    return banana_chunks


def banana_decode(banana_chunks):
    logger.debug("received: " + repr(banana_chunks))

    hashfun = BANANA_HASH
    bpw = BANANA_BPW
    banana_decode_cmd = [
        "python2",
        # BANANAPHONE_PATH,
        "-mbananaphone.bananaphone",
        "pipeline",
        'rh_decoder("words,%s,%s")' % (hashfun, bpw),
    ]

    # cenc = content.encode()
    unbanana_chunks = []
    for chunk in banana_chunks:
        b_dec = subprocess.Popen(
            banana_decode_cmd,
            stdout=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )
        # communicate() will close stdout after itself
        unbanana_chunk, comretval = b_dec.communicate(input=chunk)
        unbanana_chunks.append(unbanana_chunk)

    # Bananaphone emits tokens with trailing null bytes. We want to
    # remove these. EDIT: No we don't?

    # unbanana_chunks = [ c.strip(b'\x00') for c in unbanana_chunks ]
    # unbanana_chunks = [ c[:-1] for c in unbanana_chunks ]

    return unbanana_chunks


async def say(msg, key, bp_encoder_instance):
    """# STEPS:
    # compress
    # (hex encode)
    # encrypt
    # erasure code
    # banana code"""
    logger.debug("")
    logger.info("received: " + repr(msg))

    BP_Encoder = bp_encoder_instance

    if COMPRESSION_ON:
        ushx_compressed = ushx_cmp_bytes = bytes(compress(msg))
        # if we encrypt with null bytes, the null bytes will take up space
        ushx_compressed = ushx_compressed.strip(b"\x00")

        compressed = ushx_compressed
        logger.info("compressed: " + repr(compressed))
    else:
        compressed = bytes(msg, "utf-8")

    b16_bytes = base64.b16encode(compressed)
    encoded = b16_bytes.decode()
    logger.info("encoded:   " + repr(encoded))

    esay = pyffx.String(key, alphabet=FFX_ALPHABET, length=len(encoded))
    encrypted = esay.encrypt(encoded)

    chars_ = len(encrypted)
    bits_ = len(encrypted) * (CHARBASE / 2)

    logger.info("encrypted: {} ({} chars, {} bits)", repr(encrypted), chars_, bits_)

    if FEC_ON:
        fec_encoded = encode_to_fec(encrypted)
        logger.info("fec_encoded: {}", fec_encoded)
    else:
        # coerce it into a list to match FEC style
        fec_encoded = [encrypted]

    # banana_chunks = banana_encode(fec_encoded)
    # banana_chunks = trio.run( banana_encode, fec_encoded, BP_Encoder )

    banana_chunks = await banana_encode(fec_encoded, BP_Encoder)
    logger.info("banana_chunks: ({}) {}", str(len(banana_chunks)), repr(banana_chunks))

    chant = serialize(banana_chunks)

    retval = chant
    return retval


def hear(chant, key):
    """
    # REVERSE STEPS:
    # banana DEcode
    # erasure DEcode
    # DEcrypt
    # (hex DEcode)
    # DEcompress
    """
    logger.debug("")
    logger.info("received: {}", repr(chant))

    banana_chunks = deserialize(chant)

    unbanana_chunks = banana_decode(banana_chunks)
    logger.info("unbanana_chunks: {}", repr(unbanana_chunks))

    if FEC_ON:
        fec_decoded = decode_from_fec(unbanana_chunks)
        logger.info("fec_decoded: {}", repr(fec_decoded))
    else:
        # we coerced it into a list when we encoded w/o FEC, now we'll
        # just take it out
        fec_decoded = unbanana_chunks[0]
        # fec_decoded = fec_decoded[:-1]
        fec_decoded = fec_decoded.decode()

    # the decrypter can't handle null bytes, we want to remove any if
    # present. Not sure why this is necessary, maybe we should be
    # doing something somewhere else to ensure null bytes don't show
    # up.
    fec_decoded = fec_decoded.strip("\x00")
    logger.info("ciphertxt: {}", repr(fec_decoded))

    logger.debug("{}, {}", repr(key), repr(FFX_ALPHABET)) # WARNING: SECURITY RISK
    ehear = pyffx.String(key, alphabet=FFX_ALPHABET, length=len(fec_decoded))
    decrypted = ehear.decrypt(fec_decoded)
    logger.info("decrypted: {}", repr(decrypted))

    decoded = base64.b16decode(decrypted)

    # NOTE BUG
    decoded = decoded  # + (b'\x00')
    logger.info("decoded: " + repr(decoded))

    if COMPRESSION_ON:
        decompressed = decompress(decoded)
        logger.info("decompressed: " + repr(decompressed))
    else:
        decompressed = decoded

    return decompressed


################################################################################
################################################################################

"""Function to count total bits in a number.
https://www.geeksforgeeks.org/python-bin-count-total-bits-number/ """


def countTotalBits(num):
    # convert number into it's binary and
    # remove first two characters 0b.
    binary = bin(num)[2:]
    return len(binary)


def calc_k_m(data):
    """Do a bit of math based on the relationships between:

    how much data we have to transmit (datasize);

    bits per word = how much data/information we can store per
    word/token (size of our dictionary);

    charbase = how many chars are in our encoding alphabet (e.g. hex,
    base32);


    desired redundancy level/loss tolerance (e.g. we can lose 1/4 of
    the words and still recover the message);

    required shares;

    total shares;

    We need chunksize to calc req/totshares.

    Having a preset redundancy level allows us to map k<->m (both
    ways). The reqshares are what's really key for the data we can
    hold (payload size). All our data must fit into reqshares; the
    extra shares just hold redundancy data.

    So, we should derive totshares *from* reqshares
    (reqshares->totshares; aka totshares<-reqshares), not the other
    way around.

    TBD: this function can probably decomposed into 2 functions.

    """ ""
    data_size = len(data)
    logger.debug("datasize= {}", data_size)

    # chunksize = chunk_carrying_limit = 12 # 12 bits per word or whatever
    bpw = bits_per_word = 20
    # at what point did i hardcode this instead of using BANANA_BPW?
    logger.info("bpw= {}", bpw)

    charbase = CHARBASE
    logger.info("charbase= {}", charbase)

    # Using 12-bit words, we can hold 3 hex chars per word: 2**12 =
    # 16**3 = 4096.  Using 15-bit words, we can hold 3 b32 chars per
    # word: 2**15 = 32**3 = 32768.  This means we can solve for x
    # (using logarithms): 2**15 = 32**x = 32768.  Formula: (2**bpw =
    # charbase**cpw = valueSpace).
    #
    # So, based on bpw and the charbase, we can find out how many of
    # those chars we can fit into each dictionary word.

    # http://mathcentral.uregina.ca/QQ/database/QQ.09.02/nathan1.html
    cpw = chars_per_word = math.log(2 ** bpw) / math.log(charbase)
    logger.info("cpw= {}", cpw)

    chunksize = cpw

    # This is *before* calculating in the space used by zfec
    # headers. We will need to account for the space used by headers.
    #
    # forgot why -1, was just testing values to see results.
    chunksize = chunksize - 1
    logger.debug("chunksize= {}", chunksize)

    # zfec doesnt have any parameters for how big to make the
    # shfiles. So, we need to figure out a max_chunksize
    # (->max_shfile_size). And then make our chunks that size or
    # smaller (based on the header overhead), and feed zfec the k,m
    # parameters that will enduce its result to be the size we want.
    #
    # Basically, if we tell zfec to make a LOT of chunks, then the
    # chunks should end up small.

    reqshares = math.ceil(data_size / chunksize)
    if reqshares < 1:
        reqshares = 1

    redun = REDUNDANCY
    # Formula: req = (2/3)*tot ; so... tot = req / (2/3)
    totshares = math.floor(reqshares / redun)
    # For totshares, could do floor or ceil. Floor means more
    # redundancy.
    if totshares < 2:
        totshares = 2  # zfec wants at least 2 infiles

    # logger.info('m=tot= {}, k=req= {}', totshares, reqshares)
    logger.info("k=req= {}, m=tot= {}", reqshares, totshares)

    k, m = reqshares, totshares

    payload_size = k * chunksize  # According to zfec manpage. is this
    # accurate? what about headers?
    logger.debug("payload_size= {}", payload_size)

    return (k, m)


def encode_to_fec(payload_data):
    """Take a string; return a list/tuple of strings.

    Take a payload (data), send it thru zfec, return back the encoded
    chunks as a list.

    In order to do this, we need to supply zfec with some additional
    info.  The zfec function requires 6 arguments:

    zfec.filefec.encode_to_files(in_file, fsize, output_dir,
                                 prefix, reqshares, totshares)

    encode_to_files() will *create* the output files, but it does not
    return the files. It returns a retval (0 or 1).

    We will need to find these files afterwards, read their contents
    and place them in a structure. We then return that structure.

    in_file = tmpfile where we wrote the payload to;
    fsize = tmpfile.length;
    output_dir = tmpdir;
    prefix = 'fec_encoded' #whatever;
    reqshares = calc_k_m(payload)[0] OR calc_k_m(tmpfile)[0];
    totshares = calc_k_m(...)[1];

    """
    logger.debug("encoding to fec...")
    # print('received:', payload_data)

    reqshares, totshares = calc_k_m(payload_data)  # based off fsize or data size
    k, m = reqshares, totshares

    input__ = payload_data

    tmpdir = tempfile.mkdtemp()
    predictable_filename = "data_for_fec.data"

    # Ensure the file is read/write by the creator only
    saved_umask = os.umask(int("0077", 8))

    path = os.path.join(tmpdir, predictable_filename)
    try:
        # Open the file such that it will be discarded after.
        with open(path, "w+") as tmp:  # w+ is write but also r?

            # Write the payload data to a file so that zfec can handle it.
            logger.debug("writing to: {}", path)
            tmp.write(input__)
            tmp.seek(0, 0)  # back to start of file after writing
            contents = tmp.read()  # this is apparently doing some work
            # but i dont know what

            # print('tmp-contents:', contents)

            fsize = tmp.tell()
            logger.info("fsize=" + repr(fsize))

            output_dir = tmpdir
            prefix = "sh"  #'shfile'

            # Zfec expects a file opened as readable binary ('rb'). We
            # opened it as writeable text ('w+'). So...
            tmp.close()  # We need to close the file
            in_file = open(path, "rb")  # And reopen it as 'rb'

            # The zfec function returns a 0/1 retval, not the files.
            zfec_retval = fec.encode_to_files(in_file, fsize, output_dir, prefix, k, m)
        # End 'with' scope.

        # Now we will read the fec-encoded outfiles. First we find
        # them.
        fec_encoded_files = [f for f in glob.glob(tmpdir + "/*.fec")]
        logger.debug("reading from: {}", repr(fec_encoded_files))

        # Then we read their data and store it in a var.
        fec_encoded_chunks = [open(f, "rb").read() for f in fec_encoded_files]
        # print('encoded-chunks:', repr(fec_encoded_chunks))

        # print('fsizes: ', repr( [len(open(f, 'rb').read()) for f in fec_encoded_files] ))

    except IOError as e:
        print("IOError:")
        logger.error(e)
    else:
        # print('Deleting this:', path)
        # os.remove(path)  # Delete the tmp file.
        pass
    finally:
        # Apply the permissions from earlier. TBD: do this at
        # beginning.
        os.umask(saved_umask)

        logger.debug("Deleting this: {}", tmpdir)
        shutil.rmtree(tmpdir)  # Delete the whole tmpdir

    # Now we're all done, we return the thing we want: the fec-encoded chunks.
    logger.debug("chunksize-len= {}", [len(c) for c in fec_encoded_chunks])
    bitchunks = [bin(int.from_bytes(c, sys.byteorder))[2:] for c in fec_encoded_chunks]
    # print('bitchunks:', bitchunks)
    logger.debug("bitchunks-len= {}", [len(c) for c in bitchunks])

    return fec_encoded_chunks


def decode_from_fec(fec_encoded_chunks):
    """Takes a list/tuple of strings/binary file contents data; returns a string.

    Zfec expects to work with files.  So we will need to receive this
    list, write each one to a tempfile, then feed those tempfiles to
    zfec's decode_from_files() as [infiles]. We also need to create a
    tempfile to hold the decoded output <outf>.

    zfec's decode_from_files() expects two args: outf, infiles

    outf: We need to create a tempfile to hold the decoded
    output. Destroy this tempfile as soon as we have retrieved the
    data and -> string, which we return as retval.

    infiles: This needs to be list of file paths (or file objects??
    paths i think ). zfec will read from them, and use their content
    to reconstruct the original data. We can destroy these too, as
    soon as zfec has got the data out.

    """
    logger.debug("")
    # print('received:' , repr(fec_encoded_chunks))

    tmpdir = tempfile.mkdtemp()

    # Ensure the file is read/write by the creator only
    saved_umask = os.umask(int("0077", 8))

    try:
        infile_infix = "_shfile_"
        # Let's make some infiles
        logger.debug("writing to: {}", tmpdir)

        paths = []
        for chunk in fec_encoded_chunks:
            chunk_index = str(fec_encoded_chunks.index(chunk))
            fname = infile_infix + chunk_index
            path = os.path.join(tmpdir, fname)
            # print('writing to:', path)
            with open(path, "wb") as tmp:
                tmp.write(chunk)  # binary/str/bytstring manip first?
                # print('wrote it')
            # end 'with'
            paths.append(fname)  # for debugging
        logger.debug("these are the files we wrote: {}", paths)

        # Now we feed zfec the chunk/share files. First we find them.
        infiles = [f for f in glob.glob(tmpdir + "/*" + infile_infix + "*")]
        # instead of glob we could also append each path to infiles
        # when we write them...
        # print('infiles_paths: ' + repr(infiles))

        # Prepare a place to store the decoded/reconstructed payload
        outf_name = "reconstructed_payload.data"  # tempfile to store the data
        outf_path = os.path.join(tmpdir, outf_name)
        # print('outf_path:', outf_path)

        # Open the files in appropriate modes
        infiles = [open(f, "rb") for f in infiles]  # read
        outf = open(outf_path, "wb")  # write

        # TODO BUG: currently we are not closing files properly!

        # Then we feed the chunks to zfec decode files function.
        try:
            fec_retval = fec.decode_from_files(outf, infiles)
        except AssertionError as e:
            logger.error(
                "failed to decode from FEC: assertion error",
            )
            raise
        except:
            logger.error(
                "failed to decode from FEC",
            )
            raise
        finally:
            outf.close()  # done writing outf

        # Now we pull the output data out of the tempfile.  Open the
        # outf, read the contents into a string.
        with open(outf_path, "r") as tmp:  # text mode
            logger.debug("reading from: {}", outf_path)
            encrypted_payload = tmp.read()
        # print('payload:', repr(encrypted_payload))

    except IOError as e:
        logger.error("IOError:")
        print(e)
    else:
        # print('Deleting this:', path)
        # os.remove(outf_path)  # Delete the tmp file.
        pass
    finally:
        os.umask(saved_umask)  # Apply the permissions from earlier
        logger.debug("Deleting this: {}", tmpdir)
        shutil.rmtree(tmpdir)  # Delete the whole tmpdir

    # Now we're all done, we return the thing we want: the (encrypted) payload.
    # print('encrypted_payload:' , repr(encrypted_payload))
    return encrypted_payload


####################################
####################################


def serialize(banana_chunks):
    """Serialize the banana chunks into something human-friendly. Output
    should look like:

        'yogurt-unvarying shimmy-acutely'

    """
    logger.debug("executing serialize...")

    # First step: Format each banana chunk internally the way we want
    # them for the final user-facing chant.
    #
    # Note: this will break depending on what tokenizer is used by
    # bananaphone. (Works with tokenizer 'words'.)
    chant_chunks = []
    for c in banana_chunks:
        cindex = banana_chunks.index(c)

        # Decode from bytestring to chars. replace() and append()
        # both only work on str, not bytestrings. count() needs it
        # too.
        c = c.decode()

        # Nice to know how many words in a chunk. Number of spaces
        # *including* the trailing space, should = number of words.
        logger.info("tokens in chunk #{}= {}", cindex, c.count(" "))

        # Removes the trailing space. This trailing space is necessary for
        # decoding, so we will need to add it back on after receiving the
        # chant.
        c = c.strip()

        # Swap out the bananaphone token dividers for our own
        # (default: space->hyphen).
        c = c.replace(" ", BANANA_SPLIT_CHAR)

        chant_chunks.append(c)
    # print('chant_chunks=', repr(chant_chunks))

    # Second step: each individual chunk was formatted in previous
    # step. Now we string the chunks together into one big string.
    chant_string = ""
    for s in chant_chunks:
        chanta = s + CIPHERCHANT_SPLIT_CHAR
        chant_string += chanta
    # Remove the final divider we just put on.
    chant_string = chant_string.strip(CIPHERCHANT_SPLIT_CHAR)

    # print('chant_string=', repr(chant_string))
    logger.debug("end")
    return chant_string


def deserialize(chant_string):
    """Take a "serialized" chant string and turn it into banana chunks
    (form that banana decoder can receive.)

    """
    logger.debug("executing deserialize...")

    # First step: chunk the chant, to produce reconstructed chant chunks. :)
    chant_chunks = chant_string.split(CIPHERCHANT_SPLIT_CHAR)
    # print('chant_chunks=', repr(chant_chunks) )

    # Second step: reformat each chunk, to produce valid banana chunks.

    banana_chunks = []
    for cc in chant_chunks:
        # swap token dividers (default: hyphens->spaces);
        cc = cc.replace(BANANA_SPLIT_CHAR, " ")
        # reencode from str to bytestring;
        cc = cc.encode()
        # add back on the trailing char(s) (space by default);
        cc = cc + b" "
        banana_chunks.append(cc)

    # print('banana_chunks=', repr(banana_chunks))

    return banana_chunks


###########################################################

# def cli():
#     fire.Fire(greet)


def main():
    fire.Fire(CipherChant)

    # cc.enchant(_anyio_backend='trio')


if __name__ == "__main__":
    main()
