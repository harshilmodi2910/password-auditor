"""Identify a hash's algorithm from its format.

Detection is by prefix (bcrypt, argon2 and so on) or by hex length. Hex
length is a guess, because many unrelated algorithms share a length.
Ratings for the result and the --algorithm override come later.
"""

import re
from dataclasses import dataclass

BROKEN = "broken"
UNSUITED = "unsuited"
ACCEPTABLE = "acceptable"

@dataclass(frozen=True)
class Algorithm:
    key: str
    name: str
    tier: str
    reason: str


_SHA2_REASON = (
    "No known practical attack on the hash itself, but it is fast and has no "
    "built-in salt or work factor, so it is the wrong tool for storing passwords."
)

ALGORITHMS = {
    a.key: a
    for a in [
        Algorithm("md5", "MD5", BROKEN,
                  "Collisions have been practical for a long time, and it is very fast to compute, "
                  "which helps anyone guessing passwords."),
        Algorithm("sha1", "SHA-1", BROKEN,
                  "A real collision was published in 2017, and like MD5 it is fast to compute."),
        Algorithm("ntlm", "NTLM", BROKEN,
                  "Unsalted MD4 of the password. Fast to compute, and identical passwords give "
                  "identical hashes."),
        Algorithm("lm", "LM", BROKEN,
                  "Uppercases the password and hashes two 7-character halves separately. Obsolete."),
        Algorithm("sha224", "SHA-224", UNSUITED, _SHA2_REASON),
        Algorithm("sha256", "SHA-256", UNSUITED, _SHA2_REASON),
        Algorithm("sha384", "SHA-384", UNSUITED, _SHA2_REASON),
        Algorithm("sha512", "SHA-512", UNSUITED, _SHA2_REASON),
        Algorithm("md5crypt", "md5crypt ($1$)", BROKEN,
                  "Salted, but built on MD5 with a fixed, small number of rounds."),
        Algorithm("sha256crypt", "sha256crypt ($5$)", ACCEPTABLE,
                  "Salted and iterated, but not memory-hard. bcrypt, scrypt or argon2 are better picks."),
        Algorithm("sha512crypt", "sha512crypt ($6$)", ACCEPTABLE,
                  "Salted and iterated, but not memory-hard. bcrypt, scrypt or argon2 are better picks."),
        Algorithm("bcrypt", "bcrypt", ACCEPTABLE,
                  "Salted and deliberately slow. The cost factor matters, and bcrypt ignores "
                  "everything past 72 bytes of the password."),
        Algorithm("scrypt", "scrypt", ACCEPTABLE,
                  "Salted and memory-hard. The parameters decide how strong it really is, "
                  "and this tool does not read them."),
        Algorithm("argon2", "Argon2", ACCEPTABLE,
                  "Salted and memory-hard, and the winner of the Password Hashing Competition. "
                  "The parameters decide how strong it really is, and this tool does not read them."),
        Algorithm("pbkdf2", "PBKDF2", ACCEPTABLE,
                  "Salted and iterated, but not memory-hard. The iteration count matters."),
    ]
}

_HEX_LENGTHS = {
    32: ["md5", "ntlm", "lm"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512"],
}

_HEX = re.compile(r"[0-9a-fA-F]+")
_BCRYPT = re.compile(r"\$2[abxy]?\$(\d{2})\$[./A-Za-z0-9]{53}")
_ARGON2 = re.compile(r"\$argon2(?:id|i|d)\$.+")
_SCRYPT = re.compile(r"(?:\$scrypt\$|\$7\$).+")
_MD5CRYPT = re.compile(r"\$1\$[^$]{0,8}\$[./A-Za-z0-9]{22}")
_SHA256CRYPT = re.compile(r"\$5\$(?:rounds=\d+\$)?[^$]{0,16}\$[./A-Za-z0-9]{43}")
_SHA512CRYPT = re.compile(r"\$6\$(?:rounds=\d+\$)?[^$]{0,16}\$[./A-Za-z0-9]{86}")
_PBKDF2_PASSLIB = re.compile(r"\$pbkdf2(?:-(sha1|sha256|sha512))?\$(\d+)\$.+")
_PBKDF2_DJANGO = re.compile(r"pbkdf2_(sha1|sha256)\$(\d+)\$.+")


def detect_hash(text):
    """Return the algorithms a hash string could be, best format match first.

    An empty list means the format was not recognised.
    """
    h = text.strip()

    if _BCRYPT.fullmatch(h):
        return [ALGORITHMS["bcrypt"]]

    if _ARGON2.fullmatch(h):
        return [ALGORITHMS["argon2"]]
    if _SCRYPT.fullmatch(h):
        return [ALGORITHMS["scrypt"]]
    if _MD5CRYPT.fullmatch(h):
        return [ALGORITHMS["md5crypt"]]
    if _SHA256CRYPT.fullmatch(h):
        return [ALGORITHMS["sha256crypt"]]
    if _SHA512CRYPT.fullmatch(h):
        return [ALGORITHMS["sha512crypt"]]

    if _PBKDF2_PASSLIB.fullmatch(h) or _PBKDF2_DJANGO.fullmatch(h):
        return [ALGORITHMS["pbkdf2"]]

    if _HEX.fullmatch(h) and len(h) in _HEX_LENGTHS:
        return [ALGORITHMS[k] for k in _HEX_LENGTHS[len(h)]]

    return []
