"""Password strength scoring and rough brute force time estimates.

The score is a plain rule-based point system. The time estimates use the
usual "charset size to the power of length" math and are kept separate from
the score on purpose (see the design notes in the README).
"""

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_WORDLIST = Path(__file__).parent / "data" / "common_passwords.txt"

# Point weights. They add up to 100. These are my own picks, nothing here
# comes from a study, so change them if they feel off.
LENGTH_MAX_POINTS = 40
LENGTH_FULL_AT = 16          # this many characters earns all the length points
VARIETY_POINTS_PER_CLASS = 7.5   # four classes, so 30 total
PATTERN_MAX_POINTS = 10
PATTERN_PENALTY = 5          # taken off per kind of pattern found
DISTINCT_MAX_POINTS = 20
DISTINCT_FULL_AT = 12        # this many different characters earns all of them

# Hard caps applied after the points are added up.
COMMON_PASSWORD_CAP = 10
UNDER_6_CAP = 24
UNDER_8_CAP = 44

LABELS = [
    (85, "Strong"),
    (65, "Good"),
    (45, "Fair"),
    (25, "Weak"),
    (0, "Very Weak"),
]

# Assumed guess rates. These are round numbers I picked to show the spread
# between scenarios. None of them were measured by this project.
# (key, display name, guesses per second, how the rate is described)
GUESS_SCENARIOS = [
    ("online_throttled", "Online, rate limited", 100 / 3600, "100 guesses/hour"),
    ("online_unthrottled", "Online, no limit", 1_000, "1,000 guesses/second"),
    ("offline_slow_hash", "Offline, slow hash", 10_000, "10,000 guesses/second"),
    ("offline_fast_hash", "Offline, fast hash", 10_000_000_000, "10 billion guesses/second"),
]

# Size of each character pool used for the estimate. Non-ASCII characters get
# a flat 100, which is a placeholder and not a real count.
POOL_SIZES = {"lower": 26, "upper": 26, "digit": 10, "symbol": 33, "other": 100}

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
SECONDS_PER_YEAR = 31_557_600


@dataclass
class Estimate:
    key: str
    name: str
    rate_description: str
    guesses_per_second: float
    log10_seconds: float
    human: str


@dataclass
class StrengthResult:
    score: int
    label: str
    length: int
    classes: list
    pool_size: int
    in_common_list: bool
    issues: list = field(default_factory=list)
    estimates: list = field(default_factory=list)

    def to_dict(self):
        return {
            "score": self.score,
            "label": self.label,
            "length": self.length,
            "character_classes": self.classes,
            "pool_size": self.pool_size,
            "in_common_list": self.in_common_list,
            "issues": self.issues,
            "estimates": [
                {
                    "scenario": e.key,
                    "assumed_rate": e.rate_description,
                    "average_time": e.human,
                    "log10_seconds": round(e.log10_seconds, 2),
                }
                for e in self.estimates
            ],
        }


def load_wordlist(path=None):
    """Read a one-password-per-line file into a set of casefolded strings."""
    path = Path(path) if path else DEFAULT_WORDLIST
    words = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word:
                words.add(word.casefold())
    return words


def character_classes(password):
    classes = []
    if any(c.islower() and c.isascii() for c in password):
        classes.append("lower")
    if any(c.isupper() and c.isascii() for c in password):
        classes.append("upper")
    if any(c.isdigit() and c.isascii() for c in password):
        classes.append("digit")
    # space counts as a symbol here
    if any(c.isascii() and not c.isalnum() for c in password):
        classes.append("symbol")
    if any(not c.isascii() for c in password):
        classes.append("other")
    return classes


def _step(a, b):
    """+1 or -1 if b follows or precedes a in the alphabet or digits, else 0."""
    if a.isascii() and b.isascii() and a.isalnum() and b.isalnum():
        diff = ord(b) - ord(a)
        if diff in (1, -1):
            return diff
    return 0


def find_sequences(text):
    """Runs of 3 or more like abc, 789 or cba."""
    text = text.lower()
    runs = []
    run_start = 0
    run_step = 0
    for i in range(1, len(text)):
        step = _step(text[i - 1], text[i])
        if step != 0 and step == run_step:
            continue
        if run_step != 0 and i - run_start >= 3:
            runs.append(text[run_start:i])
        if step != 0:
            run_start = i - 1
            run_step = step
        else:
            run_start = i
            run_step = 0
    if run_step != 0 and len(text) - run_start >= 3:
        runs.append(text[run_start:])
    return runs


def find_repeats(text):
    """Runs of 3 or more of the same character, like aaa."""
    return [m.group(0) for m in re.finditer(r"(.)\1{2,}", text, re.DOTALL)]


def _label_for(score):
    for floor, label in LABELS:
        if score >= floor:
            return label
    return LABELS[-1][1]


def format_duration(log10_seconds):
    """Turn a log10 of seconds into a deliberately coarse phrase.

    Working in logs because a long password gives a number far too big for
    a float. Everything is rounded to one significant figure so the output
    doesn't suggest more precision than the inputs have.
    """
    if log10_seconds < 0:
        return "under a second"

    # 1e30 seconds is far past a trillion years, and going much further
    # would overflow the float in 10 ** x
    if log10_seconds > 30:
        return "over a trillion years"

    seconds = 10 ** log10_seconds

    if seconds < SECONDS_PER_MINUTE:
        return _phrase(seconds, "second")
    if seconds < SECONDS_PER_HOUR:
        return _phrase(seconds / SECONDS_PER_MINUTE, "minute")
    if seconds < SECONDS_PER_DAY:
        return _phrase(seconds / SECONDS_PER_HOUR, "hour")
    if seconds < SECONDS_PER_YEAR:
        return _phrase(seconds / SECONDS_PER_DAY, "day")

    years = seconds / SECONDS_PER_YEAR
    if years < 1_000:
        return _phrase(years, "year")
    if years < 1_000_000:
        return _phrase(years / 1_000, "thousand years", plural=False)
    if years < 1_000_000_000:
        return _phrase(years / 1_000_000, "million years", plural=False)
    if years < 1_000_000_000_000:
        return _phrase(years / 1_000_000_000, "billion years", plural=False)
    return "over a trillion years"


def _phrase(value, unit, plural=True):
    rounded = _round_one_sig(value)
    if plural and rounded != 1:
        unit += "s"
    return f"about {rounded} {unit}"


def _round_one_sig(x):
    if x <= 0:
        return 0
    digits = -int(math.floor(math.log10(x)))
    rounded = round(x, digits)
    return int(rounded) if rounded >= 1 else rounded


def estimate_times(length, pool_size):
    """Average-case time to find a password by trying everything.

    Average case is half the keyspace. This assumes the attacker has no
    idea how the password was made, which flatters human-picked passwords.
    """
    if length == 0 or pool_size == 0:
        return []
    log10_avg_guesses = length * math.log10(pool_size) - math.log10(2)
    estimates = []
    for key, name, rate, rate_text in GUESS_SCENARIOS:
        log10_seconds = log10_avg_guesses - math.log10(rate)
        estimates.append(
            Estimate(key, name, rate_text, rate, log10_seconds, format_duration(log10_seconds))
        )
    return estimates


def check_password(password, common_passwords=None):
    """Score a password and attach time estimates.

    common_passwords should be a set of casefolded strings from
    load_wordlist(). If it is None the bundled list is loaded.
    """
    if common_passwords is None:
        common_passwords = load_wordlist()

    length = len(password)
    classes = character_classes(password)
    pool_size = sum(POOL_SIZES[c] for c in classes)
    issues = []

    length_points = min(length, LENGTH_FULL_AT) / LENGTH_FULL_AT * LENGTH_MAX_POINTS

    # symbols and non-ASCII characters share one slot, so four slots in total
    slots = {"lower", "upper", "digit"} & set(classes)
    if "symbol" in classes or "other" in classes:
        slots.add("symbol")
    variety_points = len(slots) * VARIETY_POINTS_PER_CLASS

    repeats = find_repeats(password)
    sequences = find_sequences(password)
    pattern_points = PATTERN_MAX_POINTS
    if repeats:
        pattern_points -= PATTERN_PENALTY
        issues.append("has repeated characters (like 'aaa')")
    if sequences:
        pattern_points -= PATTERN_PENALTY
        issues.append("has a sequence (like 'abc' or '321')")
    pattern_points = max(pattern_points, 0)

    distinct = len(set(password))
    distinct_points = min(distinct, DISTINCT_FULL_AT) / DISTINCT_FULL_AT * DISTINCT_MAX_POINTS

    score = length_points + variety_points + pattern_points + distinct_points

    if length == 0:
        score = 0
        issues.append("password is empty")
    else:
        if length < 8:
            issues.append("shorter than 8 characters")
        if length < 6:
            score = min(score, UNDER_6_CAP)
        elif length < 8:
            score = min(score, UNDER_8_CAP)

    in_common_list = length > 0 and password.casefold() in common_passwords
    if in_common_list:
        issues.insert(0, "appears in the common password list")
        score = min(score, COMMON_PASSWORD_CAP)

    score = int(round(score))
    return StrengthResult(
        score=score,
        label=_label_for(score),
        length=length,
        classes=classes,
        pool_size=pool_size,
        in_common_list=in_common_list,
        issues=issues,
        estimates=estimate_times(length, pool_size),
    )
