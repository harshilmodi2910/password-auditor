# password-auditor

A Python command line tool that scores a password on length and character variety, estimates brute force times under a few assumed guess rates, and checks whether a hash's algorithm is a poor choice for storing passwords.

It is an estimator. It doesn't crack anything or recover a password from a hash, and the time estimates rest on guess rates I picked and labeled as guesses.

## Running it

Python 3.10 or newer, no dependencies. pytest is only needed for the tests.

```
python -m auditor
```

With no options it asks for a password at a hidden prompt. Here is a run through `--stdin`:

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

For a hash, `python -m auditor --hash 5f4dcc3b5aa765d61d8327deb882cf99` lists MD5, NTLM and LM as candidates (32 hex characters fits all three) and rates it weak.

Options:

- `--prompt`: hidden prompt, also the default when nothing else is given
- `--stdin`: read the password from the first line of standard input
- `--password PW`: password on the command line
- `--hash HASH`: check a hash, and don't ask for a password if it is the only option
- `--algorithm NAME`: skip detection and name the hash type, needs `--hash`
- `--wordlist FILE`: your own common password list instead of the bundled one
- `--json`: JSON output

The three password options can't be combined with each other, but any of them works with `--hash`. I kept `--password` for quick tries and scripts, though it ends up in shell history and the process list, so the tool prints a warning every time. The report never echoes the password. Bad input (unreadable wordlist, unknown algorithm, empty hash) exits with code 2.

## How the score works

Four parts add up to 100:

| Part | Points | Detail |
| --- | --- | --- |
| Length | 40 | Full at 16 characters |
| Variety | 30 | 7.5 each for lowercase, uppercase, digits, symbols |
| Patterns | 10 | Minus 5 each for repeats (`aaa`) and sequences (`abc`, `321`) |
| Distinct characters | 20 | Full at 12 different characters |

Then caps: a password in the common list can't score above 10, under 6 characters can't pass 24, under 8 can't pass 44. Labels are Very Weak up to 24, Weak up to 44, Fair up to 64, Good up to 84, and Strong from 85.

The weights are my own picks and there is no study behind them. They are constants at the top of `auditor/strength.py`.

The common list is `10k-most-common.txt` from SecLists (MIT, license copied into `auditor/data/`). Matching is exact and ignores case, so `p@ssword` only counts if that exact string is in the file.

## Brute force estimates

The time is half of all possible combinations (the average case) divided by a guess rate. Combinations are the pool size raised to the password length. The pool is 26 lowercase, 26 uppercase, 10 digits, 33 symbols (ASCII punctuation plus space), and a flat 100 if there is any non-ASCII character, which is a placeholder.

The assumed rates are 100 guesses per hour (online, rate limited), 1,000 per second (online, no limit), 10,000 per second (offline, slow hash like bcrypt) and 10 billion per second (offline, fast hash like MD5 on dedicated hardware). I measured none of them. They are round numbers meant to show how far apart the scenarios are, and real rates depend on the hash, its settings and the hardware. Times are rounded to one significant figure so they don't look more exact than they are.

The bigger issue is that the math assumes blind brute force, and people don't pick passwords that way. See the limitations.

## Hash detection

By prefix it recognizes bcrypt, Argon2, scrypt, md5crypt (`$1$`), sha256crypt (`$5$`), sha512crypt (`$6$`), and PBKDF2 in the passlib and Django formats. By hex length it can only guess, since plain hex has no label: 32 characters is MD5, NTLM or LM, 40 is SHA-1, and 56, 64, 96 and 128 are SHA-224, 256, 384 and 512. When several fit, the rating uses the worst one. With `--algorithm` it skips detection and warns if the string doesn't look like that algorithm.

There are three ratings: broken or obsolete (MD5, SHA-1, NTLM, LM, md5crypt), wrong tool (plain SHA-2, which is fine as a hash but fast and has no salt or work factor), and OK with parameters still worth checking (bcrypt, scrypt, Argon2, PBKDF2, sha256crypt, sha512crypt).

A bcrypt hash with cost under 10 or a PBKDF2 hash under 100,000 iterations drops to "wrong tool". Those cutoffs are rough floors I chose, not official numbers, so check current guidance. scrypt and Argon2 parameters aren't read at all.

## A design decision: entropy or rules

The part I went back and forth on most was how to score the password.

Entropy looked like the obvious route: length times log2 of the pool size, one number in bits, and the same math the time estimates already use. I started down that road.

Then I looked at what it does with `Password1!`. By the formula that is ten random picks from 95 characters, which is a big number, and also one of the first things a wordlist attack tries. Entropy only describes how a password was made if it was made at random, and most aren't. That was fine for the time estimates, where blind brute force is the whole point. It wasn't fine for deciding what gets called Strong.

So I switched to rules, which brought its own problem: rules need weights, and mine are guesses. I almost went back.

I ended up with both, kept apart. The label comes from the rules, the times come from the pool math, and the report says the times only describe blind brute force. I'm still not sure that beats entropy alone. Rules were easier to explain and to test, and I cared about that more than getting the weights right. For anything real, [zxcvbn](https://github.com/dropbox/zxcvbn) does pattern matching far beyond this and is the better choice.

## Limitations

- It scores structure and checks one list. It knows nothing about dictionary words, names, dates, keyboard walks or substitutions. `Password1!` gets 80 (Good), `P@ssw0rd` gets 72 and `Summer2019!` gets 84, and I'd expect all three to fall much faster to a real wordlist attack than the estimates say.
- Repeated short blocks mostly slip through. `abababababababab` gets 61 (Fair).
- Hex length detection is a guess, and SHA-3, BLAKE2, `hash:salt` pairs and MySQL formats aren't recognized.
- The guess rates, the non-ASCII pool size and the two hash floors are all my own assumptions.

## One fact about hashing

NTLM hashes are unsalted. An NTLM hash is MD4 of the password encoded as UTF-16LE with nothing random mixed in, so two accounts with the same password have the same hash.

## Tests

```
pip install -r requirements.txt
python -m pytest
```

29 tests cover empty and very long passwords, common and strong passwords, each hash format, the algorithm override and a few CLI runs. A GitHub Actions workflow runs them on Python 3.10, 3.11 and 3.12.

## License

MIT. The bundled password list is from SecLists, also MIT.
