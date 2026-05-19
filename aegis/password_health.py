"""
Aegis AV - Password Health
Offline password strength evaluation + Have-I-Been-Pwned k-anonymity check
(only the first 5 SHA-1 hex characters are ever sent to the API).
"""

import hashlib
import logging
import re
import string

logger = logging.getLogger("Aegis.PasswordHealth")

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "111111", "iloveyou",
    "monkey", "dragon", "letmein", "trustno1", "passw0rd", "admin", "welcome",
    "password1", "1234567890", "qwerty123", "1q2w3e", "google", "hello",
    "summer2024", "winter2024", "summer2025", "winter2025",
}


def evaluate_strength(pw: str) -> dict:
    """Return strength data and a 0-100 score for a password."""
    if not pw:
        return {
            "score": 0, "label": "empty", "length": 0,
            "issues": ["No password provided"], "tips": []
        }

    score = 0
    issues = []
    tips = []

    # Length
    length = len(pw)
    if length < 8:
        issues.append("Less than 8 characters")
        tips.append("Use at least 12 characters – longer is stronger.")
    else:
        score += min(40, (length - 7) * 4)  # up to +40

    # Character classes
    classes = 0
    if re.search(r"[a-z]", pw):
        classes += 1
    if re.search(r"[A-Z]", pw):
        classes += 1
    if re.search(r"[0-9]", pw):
        classes += 1
    if re.search(rf"[{re.escape(string.punctuation)}]", pw):
        classes += 1

    score += classes * 12  # up to +48

    if classes < 3:
        tips.append("Mix uppercase, lowercase, digits and symbols.")
        issues.append("Limited character variety")

    # Common password / pattern penalties
    if pw.lower() in COMMON_PASSWORDS:
        score -= 60
        issues.append("Found in common password list")

    if re.fullmatch(r"(.)\1+", pw):
        score -= 30
        issues.append("Repeated single character")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer)", pw.lower()):
        score -= 20
        issues.append("Sequential pattern detected")

    score = max(0, min(100, score))

    if score >= 80:
        label = "Excellent"
    elif score >= 60:
        label = "Strong"
    elif score >= 40:
        label = "Moderate"
    elif score >= 20:
        label = "Weak"
    else:
        label = "Very Weak"

    return {
        "score": score,
        "label": label,
        "length": length,
        "classes": classes,
        "issues": issues,
        "tips": tips,
    }


def check_hibp(pw: str) -> dict:
    """Query Have-I-Been-Pwned (k-anonymity) for breach exposure."""
    out = {"checked": False, "pwned": False, "occurrences": 0, "error": ""}

    if not HAS_REQUESTS:
        out["error"] = "requests library not installed"
        return out

    if not pw:
        return out

    try:
        sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=4,
            headers={"User-Agent": "Aegis-AV-PasswordHealth/2.1"},
        )
        out["checked"] = True
        if resp.status_code != 200:
            out["error"] = f"HIBP returned status {resp.status_code}"
            return out
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            hash_suffix, _, count_str = line.partition(":")
            if hash_suffix.upper() == suffix:
                try:
                    out["pwned"] = True
                    out["occurrences"] = int(count_str)
                except Exception:
                    out["occurrences"] = -1
                break
    except Exception as e:
        out["error"] = f"HIBP request failed: {e}"
    return out


def evaluate_full(pw: str, check_breach: bool = True) -> dict:
    """Return full strength + breach analysis."""
    base = evaluate_strength(pw)
    if check_breach:
        base["breach"] = check_hibp(pw)
        if base["breach"].get("pwned"):
            base["score"] = max(0, base["score"] - 40)
            base["label"] = "Compromised"
            base["issues"].append(
                f"Seen in {base['breach']['occurrences']} known data breaches"
            )
    return base
