##########################################################
def test_nlp():
    # https://www.nltk.org/book_1ed/ch03.html
    import nltk, re

    regexp = r'^[AEIOUaeiou]+|[AEIOUaeiou]+$|[^AEIOUaeiou]'
    def disemvowel(word):
        pieces = re.findall(regexp, word)
        return ''.join(pieces)

    print()
    english_udhr = nltk.corpus.udhr.words('English-Latin1')
    s = nltk.tokenwrap(disemvowel(w) for w in english_udhr[:75])
    print( s)
