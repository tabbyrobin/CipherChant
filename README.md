# Setup

`git clone ...` the repo and then

```
$ cd ProjectCipherChant/cipherchant
$ systemctl start docker ; time sudo vagrant reload ; time sudo vagrant up ; sudo vagrant docker-exec -it -- /usr/bin/fish
# poetry install
```

`poetry install` gets (almost) all the dependencies installed.

The one dependency poetry doesn't install: bananaphone. It's python2,
not 3.  The Vagrant/docker setup will get it installed.

# Testing

After setup, `poetry shell` and then usage to test:

`cipherchant enchant 'hi'` (anything for passphrase, for example 'p')

`cipherchant disenchant "bookmaking-corsair-alighting-caramels"` (this
was encoded with passphrase 'p', and default bpw 13.)

No `tests/` are written yet.

passphrase: 'p'
```
# poetry run cipherchant enchant "hi"
# poetry run cipherchant disenchant "pursued-jottings-classifications-underpaid"
```

# TBD

* rip out the async code and replace with basic multiprocess
  setup. Async is cool but not actually useful for this use case.
* clean up code, make classes
* maybe integrate alternative compression scheme (arithmetic
  encoding).  -> Find good statistical heuristics (maybe ML) to judge
  when we have guessed/brute-forced the right decoding parameters.
* use NLP to generate/curate a good token-list with short /sentences/
  as tokens (more bits per token)
* implement a TUI/ncurses (pytermgui? py_cui? textual? picotui?)
* port bananaphone to py3
* implement sideloading for pre-calculated hashtables for bananaphone

# Misc

podman would be great but didnt seem to work...

backwards:
```
sudo dnf remove podman-docker moby-engine -y; sh ./get-docker.sh ; systemctl start docker
DRY_RUN=1 sh ./get-docker.sh
curl -fsSL https://get.docker.com -o get-docker.sh
```
