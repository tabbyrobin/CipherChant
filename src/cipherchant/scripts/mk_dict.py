import sys

inf = sys.stdin
outf = sys.stdout

chars = '2345689'
prefixes = chars
#suffixes = prefixes
suffixes = [x+y for x in chars for y in chars]

#with open(infp, "r"), open(outp, 'w') as inf, outf:

def mk_dict():
    for line in inf.readlines():
        word = line.strip()
        outf.write(line)
        for p in prefixes:
            for s in suffixes:
                entry = p + word + s
                outf.write(entry + '\n')


mk_dict()
