#!/usr/bin/env python2

# Local import because bananaphone is not installable. This file needs
# to be in same dir as bananaphone.py
# import bananaphone as bp

# Absolute import from an installed bananaphone (pip2 install --user -e .)
import bananaphone.bananaphone as bp

import fire
import click, sys


class Encoder:
    """Wrapper around bananaphone providing a programatically usable CLI.

    This is necessary because

    (1) the bananaphone CLI does not send a newline (or any indicator)
    that it is done transmitting.

    (2) The bananaphone API is python2, and is not compatible with
    python3.

    This wrapper is written in python2, and provides a CLI interface that
    can be interacted with from a separate python3 process.

    Currently, only encoding it implemented. Decoding does not require a
    dictionary model, so the bananaphone CLI is fine for now.

    """

    def __init__(
        self, encoding_spec=("words", "sha1", "13"), model="random", corpus="/usr/share/dict/words"
    ):

        # Unpack the spec tuple into a string. We have to set it up
        # this way because if we try to just treat it as a string,
        # fire automatically detects commas and coerces it into a
        # tuple anyway. :/
        w, h, b = encoding_spec
        encoding_spec = "%s,%s,%s" % (w, h, b)

        notify("Loading rh_encoder with these parameters...")
        notify(repr(encoding_spec))
        notify(repr(model))
        notify(repr(corpus))

        try:
            # load the encoder up
            self.ENCODER = bp.rh_encoder(encoding_spec, model, corpus)

            # programs calling this will need to know when the encoder
            # is loaded, so they can detect that, before sending data
            # to encode.
            notify("ENCODER READY")
        except AssertionError as e:
            notify("FAILED TO LOAD ENCODER")
            click.echo(e, err=True)
            sys.exit(1)  # exiting manually is non-ideal but cant see a
            # better way here

        try:
            # and wait for input (on infinite loop)
            while True:
                notify("text to encode")
                value = click.prompt("Enter text to encode", type=str, err=True)
                notify("text to encode")
                notify("click prompt value: " + value)

                encoded = self.encode(value)
                print(encoded)  # print() will add \n for us

                # fixes bug where script works in IPython but not in
                # terminal (BlockingIOError)
                sys.stdout.flush()

        except click.exceptions.Abort as e:
            click.echo(e, err=True)
            sys.exit(0)  # exit cleanly without getting a Fire manpage

    def encode(self, data):
        notify("received this for encoding: " + repr(data))

        # this kludge fixes truncated end bug. Supposedly
        # changeWordSize() is supposed to take care of this but
        # apparently it's not.
        #
        # TBD: find root problem and either remove this or make it add
        # only how many it needs.
        data = bytes(unicode(data) + "\x00\x00\x00")
        notify("sending this to bananaphone:" + repr(data))

        # From the bananaphone docs:
        #
        # "For streaming operation, the word size needs to be a factor
        # or multiple of 8. (Otherwise, bytes will frequently not be
        # deliverable until after the subsequent byte has been sent,
        # which breaks most streaming applications). Implementing the
        # above-mentioned layer of timing cover would obviate this
        # limitation. ...
        #
        # ... Also, when the word size is not a multiple or factor of
        # 8, there will sometimes be 1 or 2 null bytes added to the
        # end of the message (due to ambiguity when converting the
        # last word back to 8 bits)."

        # this uses bananaphone's 'composable coroutines' API
        enco = "".join(data > self.ENCODER)
        return enco


def notify(s):
    """This function provides an easy way to write everything else to
    stderr. The ONLY thing we write to stdout should be the results of the
    decoding (+\n).

    """
    sys.stderr.write(s + "\n")


# dec = bp.rh_decoder('words,sha1,13')
# deco = ''.join( str(enco) > dec )

fire.Fire()
