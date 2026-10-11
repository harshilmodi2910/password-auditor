"""Identify a hash's algorithm from its format and say whether it is a weak
choice for storing passwords.

Detection is by prefix (bcrypt, argon2 and so on) or by hex length. Hex
length is a guess, because many unrelated algorithms share a length.
"""

import re
from dataclasses import dataclass, field, replace

BROKEN = "broken"
UNSUITED = "unsuited"
ACCEPTABLE = "acceptable"
UNKNOWN = "unknown"

# Rough floors I picked for the two parameterised schemes. They are not
# official numbers. Look up current guidance before relying on them.
MIN_BCRYPT_COST = 10
MIN_PBKDF2_ITERATIONS = 100_000

# Used to pick the worst one when a hash could be several algorithms.
_TIER_RANK = {ACCEPTABLE: 0, UNSUITED: 1, BROKEN: 2}


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

# Extra spellings accepted by --algorithm, after lowercasing and removing
# dashes, underscores and spaces.
_ALIASES = {
    "argon2id": "argon2",
    "argon2i": "argon2",
    "argon2d": "argon2",
    "pbkdf2sha1": "pbkdf2",
    "pbkdf2sha256": "pbkdf2",
    "pbkdf2sha512": "pbkdf2",
    "nt": "ntlm",
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


@dataclass
class HashResult:
    length: int
    requested_algorithm: str | None
    candidates: list
    format_matches: bool | None
    tier: str
    notes: list = field(default_factory=list)

    def to_dict(self):
        return {
            "length": self.length,
            "requested_algorithm": self.requested_algorithm,
            "format_matches_requested": self.format_matches,
            "tier": self.tier,
            "candidates": [
                {"algorithm": c.name, "tier": c.tier, "reason": c.reason}
                for c in self.candidates
            ],
            "notes": self.notes,
        }


def resolve_algorithm(name):
    """Map a user-supplied name like 'SHA-256' to a key in ALGORITHMS."""
    cleaned = re.sub(r"[-_ ]", "", name.strip().lower())
    cleaned = _ALIASES.get(cleaned, cleaned)
    if cleaned not in ALGORITHMS:
        supported = ", ".join(sorted(ALGORITHMS))
        raise ValueError(f"unknown algorithm '{name}'. Supported: {supported}")
    return cleaned


def _pbkdf2(digest, iterations):
    base = ALGORITHMS["pbkdf2"]
    name = f"PBKDF2-{digest.upper()}"
    if iterations < MIN_PBKDF2_ITERATIONS:
        return replace(
            base, name=name, tier=UNSUITED,
            reason=f"Iteration count is {iterations}, under the {MIN_PBKDF2_ITERATIONS} "
                   "floor this tool uses. That is a rough number I picked, not an official one.",
        )
    return replace(base, name=name)


def detect_hash(text):
    """Return the algorithms a hash string could be, best format match first.

    An empty list means the format was not recognised.
    """
    h = text.strip()

    m = _BCRYPT.fullmatch(h)
    if m:
        cost = int(m.group(1))
        base = ALGORITHMS["bcrypt"]
        if cost < MIN_BCRYPT_COST:
            return [replace(
                base, tier=UNSUITED,
                reason=f"Cost factor is {cost}, under the {MIN_BCRYPT_COST} floor this tool uses. "
                       "That is a rough number I picked, not an official one.",
            )]
        return [base]

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

    m = _PBKDF2_PASSLIB.fullmatch(h)
    if m:
        return [_pbkdf2(m.group(1) or "sha1", int(m.group(2)))]
    m = _PBKDF2_DJANGO.fullmatch(h)
    if m:
        return [_pbkdf2(m.group(1), int(m.group(2)))]

    if _HEX.fullmatch(h) and len(h) in _HEX_LENGTHS:
        return [ALGORITHMS[k] for k in _HEX_LENGTHS[len(h)]]

    return []


def check_hash(text, algorithm=None):
    """Rate a hash. If algorithm is given, trust it over format detection."""
    h = text.strip()
    if not h:
        raise ValueError("the hash is empty")

    detected = detect_hash(h)
    notes = []

    if algorithm is not None:
        key = resolve_algorithm(algorithm)
        # use the detected copy when there is one, since it carries the
        # parameter-based rating (bcrypt cost, PBKDF2 iterations)
        match = next((d for d in detected if d.key == key), None)
        candidates = [match or ALGORITHMS[key]]
        format_matches = match is not None
        if not format_matches:
            notes.append(
                f"The hash does not look like {ALGORITHMS[key].name} by format, "
                "so the rating above is for the name you gave, not for this string."
            )
    else:
        candidates = detected
        format_matches = None
        if not candidates:
            notes.append(
                "Format not recognised. Only the algorithms listed in the README are detected."
            )
        elif _HEX.fullmatch(h):
            notes.append(
                "A plain hex string carries no label, so this is a guess from length alone. "
                "Other algorithms share these lengths."
            )
        if len(candidates) > 1:
            notes.append("More than one algorithm fits. The rating uses the worst of them.")

    if candidates:
        tier = max((c.tier for c in candidates), key=lambda t: _TIER_RANK[t])
    else:
        tier = UNKNOWN

    return HashResult(
        length=len(h),
        requested_algorithm=algorithm,
        candidates=candidates,
        format_matches=format_matches,
        tier=tier,
        notes=notes,
    )
