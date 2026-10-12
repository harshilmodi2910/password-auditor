"""Turn results into text or JSON. Nothing here does any checking."""

import json

from .hash_check import ACCEPTABLE, BROKEN, UNKNOWN, UNSUITED

CLASS_NAMES = {
    "lower": "lowercase",
    "upper": "uppercase",
    "digit": "digits",
    "symbol": "symbols",
    "other": "non-ASCII",
}

TIER_TEXT = {
    BROKEN: "WEAK (broken or obsolete for passwords)",
    UNSUITED: "WEAK (wrong tool for storing passwords)",
    ACCEPTABLE: "OK (still check its parameters)",
    UNKNOWN: "UNKNOWN",
}

ESTIMATE_NOTE = (
    "Estimates assume the attacker tries every combination of the character types used, "
    "and they use assumed guess rates, not measured ones. Real attacks depend on "
    "hardware, the hash being attacked, and how the password was chosen."
)


def format_password_report(result):
    lines = ["Password strength", ""]
    lines.append(f"  Score:      {result.score}/100 ({result.label})")
    lines.append(f"  Length:     {result.length}")

    if result.classes:
        names = ", ".join(CLASS_NAMES[c] for c in result.classes)
        lines.append(f"  Uses:       {names}")
    else:
        lines.append("  Uses:       nothing (empty input)")

    if result.issues:
        lines.append("  Problems:")
        for issue in result.issues:
            lines.append(f"    - {issue}")
    else:
        lines.append("  Problems:   none found")

    if result.estimates:
        lines.append("")
        lines.append("Brute force estimate (average case)")
        lines.append("")
        if result.in_common_list:
            lines.append(
                "  This password is in the common list, so an attacker would try it "
                "almost immediately. The times below only apply to a blind brute force."
            )
            lines.append("")
        width = max(len(e.name) for e in result.estimates)
        for e in result.estimates:
            lines.append(f"  {e.name.ljust(width)}  {e.human}   (assumed {e.rate_description})")
        lines.append("")
        lines.append(f"  Pool size used: {result.pool_size} characters")
        lines.append("")
        lines.append("  " + ESTIMATE_NOTE)

    return "\n".join(lines)


def format_hash_report(result):
    lines = ["Hash check", ""]
    lines.append(f"  Length:     {result.length}")

    if result.requested_algorithm:
        lines.append(f"  Algorithm:  {result.requested_algorithm} (given by you)")
    elif result.candidates:
        names = " or ".join(c.name for c in result.candidates)
        lines.append(f"  Detected:   {names}")
    else:
        lines.append("  Detected:   nothing recognised")

    lines.append(f"  Rating:     {TIER_TEXT[result.tier]}")

    for c in result.candidates:
        lines.append("")
        lines.append(f"  {c.name}: {c.reason}")

    for note in result.notes:
        lines.append("")
        lines.append(f"  Note: {note}")

    return "\n".join(lines)


def format_json(password_result=None, hash_result=None):
    data = {}
    if password_result is not None:
        data["password"] = password_result.to_dict()
    if hash_result is not None:
        data["hash"] = hash_result.to_dict()
    return json.dumps(data, indent=2)
