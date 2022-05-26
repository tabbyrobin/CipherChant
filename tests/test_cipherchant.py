from cipherchant import __version__


def test_version():
    assert __version__ == '0.1.0'


import fire

# from cipherchant.cipherchant import greet

# def test_greet_cli(capsys):
#     fire.Fire(greet, ["Egypt"])
#     captured = capsys.readouterr()
#     result = captured.out
#     assert "Hello, Egypt!" in result

from cipherchant.cipherchant import CipherChant

# def test_enchant_cli(capsys):
#     fire.Fire(CipherChant, ["enchant", "\"hello\"", "--p=tests/data/passphrase_0.file.txt"])
#     captured = capsys.readouterr()
#     result = captured.out
#     return result

# def test_disenchant_cli(capsys):
#     chant, orig = "wiretapping-Pitt's-cranberries-wielded", "hi"
#     chant, orig = "elevators-besiegers-Moselle's-indecisively-Parsons's-penny", "hello"
#     fire.Fire(CipherChant, ["disenchant", chant, "--p=tests/data/passphrase_0.file.txt"])
#     captured = capsys.readouterr()
#     result = captured.out
#     assert orig in result
#     return result

# def test_enchant_disenchant_cli():
#     enchanted = test_enchant_cli()
#     disenchanted = test_disenchant_cli()

def test_enchant_disenchant():
    pfilepath = "tests/data/passphrase_0.file.txt"
    msg = "hello"

    p = CipherChant(p=pfilepath)
    chant = p.enchant(msg)
    disenchanted = p.disenchant(chant)
    assert disenchanted == msg
