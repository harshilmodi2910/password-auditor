# password-auditor

A command line tool written in Python that does two things. It scores a password on length and character variety and gives rough brute force times under a few assumed guess rates, and it looks at a hash and tells you whether the algorithm is a poor choice for storing passwords.

It is an estimator. It does not crack anything, it can't recover a password from a hash, and the time estimates are rough numbers built on guesses I made up and labeled as guesses (more on that below).

## Running it

Python 3.10 or newer. There are no dependencies to run it. pytest is only needed for the tests.

```
python -m auditor
```

With no options it asks for a password at a hidden prompt. Here is what a run looks like when the password comes in through `--stdin`:

```
$ printf 'Kq9#Zm2$Xv7!' | python -m auditor --stdin
Password strength

  Score:      90/100 (Strong)
  Length:     12
  Uses:       lowercase, uppercase, digits, symbols
  Problems:   none found

Brute force estimate (average case)

  Online, rate limited  over a trillion years   (assumed 100 guesses/hour)
  Online, no limit      over a trillion years   (assumed 1,000 guesses/second)
  Offline, slow hash    about 900 billion years   (assumed 10,000 guesses/second)
  Offline, fast hash    about 900 thousand years   (assumed 10 billion guesses/second)

  Pool size used: 95 characters

  Estimates assume the attacker tries every combination of the character types used, and they use assumed guess rates, not measured ones. Real attacks depend on hardware, the hash being attacked, and how the password was chosen.
```

And a hash:

```
$ python -m auditor --hash 5f4dcc3b5aa765d61d8327deb882cf99
Hash check

  Length:     32
  Detected:   MD5 or NTLM or LM
  Rating:     WEAK (broken or obsolete for passwords)

  MD5: Collisions have been practical for a long time, and it is very fast to compute, which helps anyone guessing passwords.

  NTLM: Unsalted MD4 of the password. Fast to compute, and identical passwords give identical hashes.

  LM: Uppercases the password and hashes two 7-character halves separately. Obsolete.

  Note: A plain hex string carries no label, so this is a guess from length alone. Other algorithms share these lengths.

  Note: More than one algorithm fits. The rating uses the worst of them.
```

### Options

| Option | What it does |
| --- | --- |
| `--prompt` | Read the password from a hidden prompt. This is also what happens when you give no options at all. |
| `--stdin` | Read the password from the first line of standard input. |
| `--password PW` | Check the password you typed on the command line. Prints a warning, see below. |
| `--hash HASH` | Check a hash. If you only give `--hash`, no password is asked for. |
| `--algorithm NAME` | Tell the tool what the hash is instead of detecting it. Needs `--hash`. |
| `--wordlist FILE` | Use your own common password list, one per line, instead of the bundled one. |
| `--json` | Print JSON instead of text. |

`--prompt`, `--stdin` and `--password` can't be combined with each other. You can combine any of them with `--hash`.

I kept `--password` because it is handy for scripts and for trying a few things quickly, but anything typed on the command line can end up in your shell history and shows in the process list while the command runs. The tool prints a warning to stderr every time it is used. The report never prints the password back.

Exit code is 0 on a normal run and 2 for bad input (unreadable wordlist, unknown algorithm name, empty hash, and so on).

## How the score works

The score is a point total out of 100, then some caps are applied.

| Part | Points | How it works |
| --- | --- | --- |
| Length | 40 | Scales up to 16 characters, which gets all 40. |
| Variety | 30 | 7.5 for each of lowercase, uppercase, digits, and symbols. Non-ASCII characters count in the symbols slot. |
| Patterns | 10 | Starts at 10. Minus 5 for repeated characters (`aaa`), minus 5 for a sequence (`abc`, `321`). |
| Distinct characters | 20 | Scales up to 12 different characters. |

Caps after adding up: a password found in the common list can't score above 10, anything under 6 characters can't score above 24, and anything under 8 can't score above 44.

Labels: 0 to 24 Very Weak, 25 to 44 Weak, 45 to 64 Fair, 65 to 84 Good, 85 to 100 Strong.

All the weights are my own picks. There is no study behind 40/30/10/20. They are constants at the top of `auditor/strength.py` if you want to change them.

The common list is the 10,000 line `10k-most-common.txt` file from [SecLists](https://github.com/danielmiessler/SecLists), which is MIT licensed. A copy of its license is in `auditor/data/`. Matching is exact and ignores case. It does not try letter swaps, so `p@ssword` is not caught unless that exact string is in the file.

## Brute force estimates

The time is the average case, which is half of all possible combinations, divided by an assumed guess rate. The number of possible combinations is the size of the character pool raised to the password length. Pool sizes: 26 lowercase, 26 uppercase, 10 digits, 33 symbols (the 32 ASCII punctuation characters plus space), and a flat 100 if there are any non-ASCII characters. That last 100 is a placeholder, not a real count.

The four guess rates:

| Scenario | Assumed rate |
| --- | --- |
| Online, rate limited | 100 guesses per hour |
| Online, no limit | 1,000 guesses per second |
| Offline, slow hash | 10,000 guesses per second |
| Offline, fast hash | 10 billion guesses per second |

I did not measure any of these and they are not benchmarks. They are round numbers chosen so you can see how much the scenarios differ from each other. "Offline, fast hash" stands in for a fast hash like MD5 attacked with dedicated hardware, and "Offline, slow hash" stands in for something like bcrypt. The real rate depends on the exact hash, its settings, and the attacker's hardware, and it can be far off from my numbers in either direction.

Times are rounded to one significant figure on purpose so they don't look more exact than they are.

The bigger problem is that the math assumes the attacker tries every combination of characters blindly. People don't pick passwords that way. See the limitations below.

## Hash detection

Detection works from the shape of the string, or you can pass `--algorithm` and skip detection. With `--algorithm`, the tool also tells you if the string doesn't look like that algorithm.

Recognized by prefix:

- bcrypt (`$2a$`, `$2b$`, `$2x$`, `$2y$`)
- Argon2 (`$argon2id$`, `$argon2i$`, `$argon2d$`)
- scrypt (`$scrypt$` and `$7$`)
- md5crypt (`$1$`), sha256crypt (`$5$`), sha512crypt (`$6$`)
- PBKDF2 in the passlib format (`$pbkdf2-sha256$...`) and the Django format (`pbkdf2_sha256$...`)

Recognized by hex length (a guess, because plain hex has no label):

| Length | Candidates |
| --- | --- |
| 32 | MD5, NTLM, LM |
| 40 | SHA-1 |
| 56 | SHA-224 |
| 64 | SHA-256 |
| 96 | SHA-384 |
| 128 | SHA-512 |

Each algorithm gets one of three ratings:

- **Broken or obsolete** for passwords: MD5, SHA-1, NTLM, LM, md5crypt.
- **Wrong tool**: the plain SHA-2 hashes. Nothing is wrong with them as hashes, but they are fast and have no salt or work factor built in, which is the opposite of what password storage wants.
- **OK, still check the parameters**: bcrypt, scrypt, Argon2, PBKDF2, sha256crypt, sha512crypt.

Two ratings depend on a setting. A bcrypt hash with a cost factor under 10 and a PBKDF2 hash with under 100,000 iterations get downgraded to "wrong tool". Those two cutoffs are rough floors I chose. They are not official numbers and current guidance may differ, so look it up before relying on them. The tool does not read scrypt or Argon2 parameters at all.

When a hash fits several algorithms, the rating uses the worst one.

## A design decision: entropy or rules

The part I went back and forth on most was how to score the password itself.

Entropy looked like the obvious route. One formula (length times log2 of the pool size), one number in bits, and it is the same math the brute force estimates already use, so there would be one code path instead of two. I started down that road.

Then I thought about what it does with `Password1!`. By the formula it is ten random picks from a 95 character pool, which is a big number, and it is also one of the first things any wordlist attack tries. Entropy only describes how a password was made if it was made at random, and most passwords aren't. For the time estimates I was fine with that, because the whole point there is "what if the attacker brute forces blindly". For the thing that decides whether a password gets called Strong, I wasn't.

So I switched to rules. Length, variety, patterns, distinct characters, and a hard cap for anything in the common list. That got me a different problem, which is that rules mean picking weights and my weights are guesses. I almost went back to entropy for that reason.

Where I ended up is both, kept apart. The label comes from the rules and the times come from the pool-size math, and the report says the times only describe blind brute force. I'm still not sure that is better than entropy alone. Rules were easier to explain and easier to write tests for, and that mattered more to me than getting the weights right. For anything real, [zxcvbn](https://github.com/dropbox/zxcvbn) does pattern matching far beyond what is here and would be the better choice.

## Limitations

- It scores structure and checks one list. It does not know about dictionary words, names, dates, keyboard walks, or substitutions. `Password1!` scores 80 (Good), `P@ssw0rd` scores 72 (Good), and `Summer2019!` scores 84 (Good) in this tool, and I would expect all three to fall much faster to a real wordlist attack than the estimates suggest.
- Repeating a short block is mostly invisible to it. `abababababababab` scores 61 (Fair), and a 100,000 character string made of one four character block gets a long-looking time estimate. The only thing that notices is the distinct character count.
- The time estimates assume blind brute force, assumed rates, and a character pool guessed from the characters used.
- The common list match is exact and case-insensitive only.
- Hash detection by hex length is a guess. It does not recognize SHA-3, BLAKE2, `hash:salt` pairs, MySQL formats, or anything else not listed above, and some of those share lengths with the algorithms it does list.
- The bcrypt and PBKDF2 cutoffs are my own rough floors.

## An actual fact about hashing

NTLM hashes are unsalted. An NTLM hash is MD4 of the password encoded as UTF-16LE, with nothing random mixed in, so two accounts with the same password have the same hash.

## Tests

```
pip install -r requirements.txt
python -m pytest
```

29 tests across `tests/test_strength.py`, `tests/test_hash_check.py` and `tests/test_cli.py`. They cover empty and very long passwords, common and strong passwords, the hash formats listed above, the algorithm override, and a few CLI runs. The workflow in `.github/workflows/tests.yml` runs them on Python 3.10, 3.11 and 3.12.

## Layout

```
auditor/
  strength.py     scoring and time estimates
  hash_check.py   hash detection and ratings
  report.py       text and JSON output
  cli.py          argument parsing
  __main__.py     lets you run python -m auditor
  data/           common password list and its license
tests/
```

## License

MIT, see `LICENSE`. The bundled password list is from SecLists, also MIT, and its license is in `auditor/data/SecLists-LICENSE.txt`.
