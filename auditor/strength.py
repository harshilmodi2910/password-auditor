"""Password strength scoring. First pass: length, character variety and
how many different characters are used. Patterns and the common password
list come later.
"""

from dataclasses import dataclass, field

# Point weights. They add up to 100. These are my own picks, nothing here
# comes from a study, so change them if they feel off.
LENGTH_MAX_POINTS = 40
LENGTH_FULL_AT = 16          # this many characters earns all the length points
VARIETY_POINTS_PER_CLASS = 7.5   # four classes, so 30 total
PATTERN_MAX_POINTS = 10
DISTINCT_MAX_POINTS = 20
DISTINCT_FULL_AT = 12        # this many different characters earns all of them

LABELS = [
    (85, "Strong"),
    (65, "Good"),
    (45, "Fair"),
    (25, "Weak"),
    (0, "Very Weak"),
]

# Size of each character pool. Non-ASCII characters get a flat 100, which
# is a placeholder and not a real count.
POOL_SIZES = {"lower": 26, "upper": 26, "digit": 10, "symbol": 33, "other": 100}


@dataclass
class StrengthResult:
    score: int
    label: str
    length: int
    classes: list
    pool_size: int
    issues: list = field(default_factory=list)


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


def _label_for(score):
    for floor, label in LABELS:
        if score >= floor:
            return label
    return LABELS[-1][1]


def check_password(password):
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

    # no pattern check yet, so everyone gets the full points for now
    pattern_points = PATTERN_MAX_POINTS

    distinct = len(set(password))
    distinct_points = min(distinct, DISTINCT_FULL_AT) / DISTINCT_FULL_AT * DISTINCT_MAX_POINTS

    score = length_points + variety_points + pattern_points + distinct_points

    if length == 0:
        score = 0
        issues.append("password is empty")
    elif length < 8:
        issues.append("shorter than 8 characters")

    score = int(round(score))
    return StrengthResult(
        score=score,
        label=_label_for(score),
        length=length,
        classes=classes,
        pool_size=pool_size,
        issues=issues,
    )
