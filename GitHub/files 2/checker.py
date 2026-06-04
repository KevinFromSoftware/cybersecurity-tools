#!/usr/bin/env python3
"""
Password Strength Checker - A cybersecurity learning tool
Author: [Ditt navn]
Description: Analyzes passwords and gives a security rating with feedback
"""

import re
import string
import argparse
import hashlib


# -------------------------------------------------------------------
# TOP 50 MOST COMMON PASSWORDS (from real data breaches)
# If the user's password is on this list, it's instantly crackable
# -------------------------------------------------------------------
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "monkey", "master", "dragon", "letmein", "login",
    "princess", "football", "shadow", "sunshine", "trustno1",
    "iloveyou", "batman", "access", "hello", "charlie",
    "welcome", "donald", "password1", "qwerty123", "admin",
    "passw0rd", "master123", "welcome1", "p@ssw0rd", "123qwe",
    "zaq1zaq1", "mustang", "baseball", "hunter2", "summer",
    "michael", "ashley", "jessica", "pepper", "000000",
    "computer", "internet", "samsung", "1q2w3e4r", "starwars",
}


# -------------------------------------------------------------------
# KEYBOARD PATTERNS (easy to guess via brute force)
# -------------------------------------------------------------------
KEYBOARD_PATTERNS = [
    "qwerty", "qwertz", "asdfgh", "zxcvbn",
    "1234", "2345", "3456", "4567", "5678", "6789", "7890",
    "abcdef", "bcdefg", "cdefgh",
    "!@#$%", "@#$%^",
]


# -------------------------------------------------------------------
# STRENGTH CHECKS — each returns (points, feedback_message)
# -------------------------------------------------------------------
def check_length(password: str) -> tuple:
    """Longer passwords are exponentially harder to crack."""
    length = len(password)
    if length >= 16:
        return (3, f"Excellent length ({length} characters)")
    elif length >= 12:
        return (2, f"Good length ({length} characters)")
    elif length >= 8:
        return (1, f"Acceptable length ({length} characters), but 12+ is recommended")
    else:
        return (0, f"Too short ({length} characters) — minimum 8, aim for 12+")


def check_character_types(password: str) -> tuple:
    """More character types = larger search space for attackers."""
    types_found = []
    types_missing = []

    checks = [
        (r"[a-z]",             "lowercase letters"),
        (r"[A-Z]",             "UPPERCASE letters"),
        (r"[0-9]",             "digits"),
        (r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?~`]", "special characters"),
    ]

    for pattern, name in checks:
        if re.search(pattern, password):
            types_found.append(name)
        else:
            types_missing.append(name)

    points = len(types_found)
    if types_missing:
        feedback = f"Missing: {', '.join(types_missing)}"
    else:
        feedback = "All character types present"

    return (points, feedback)


def check_common_password(password: str) -> tuple:
    """Check if the password appears in known breach lists."""
    if password.lower() in COMMON_PASSWORDS:
        return (0, "This password is in the top 50 most common — instantly crackable!")
    return (2, "Not found in common password list")


def check_patterns(password: str) -> tuple:
    """Detect keyboard walks and sequential patterns."""
    lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            return (0, f"Contains keyboard pattern '{pattern}' — easy to guess")

    # Check for repeated characters (e.g., "aaaaaa")
    if re.search(r"(.)\1{3,}", password):
        return (0, "Contains repeated characters (e.g., 'aaaa')")

    return (2, "No obvious patterns detected")


def check_repeated_words(password: str) -> tuple:
    """Detect if the same word is just repeated (e.g., 'catcat')."""
    lower = password.lower()
    length = len(lower)
    for size in range(2, length // 2 + 1):
        chunk = lower[:size]
        if chunk * (length // size) == lower[:size * (length // size)] and length // size >= 2:
            return (0, f"Just the word '{chunk}' repeated — easy to detect")
    return (1, "No simple repetition detected")


# -------------------------------------------------------------------
# ESTIMATE CRACK TIME (simplified)
# -------------------------------------------------------------------
def estimate_crack_time(password: str) -> str:
    """
    Rough estimate based on character space and length.
    Assumes 10 billion guesses/second (modern GPU cluster).
    """
    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_size += 32

    if charset_size == 0:
        return "Instant"

    combinations = charset_size ** len(password)
    guesses_per_second = 10_000_000_000  # 10 billion (GPU cluster)
    seconds = combinations / guesses_per_second

    if seconds < 1:
        return "Less than a second"
    elif seconds < 60:
        return f"About {int(seconds)} seconds"
    elif seconds < 3600:
        return f"About {int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"About {int(seconds / 3600)} hours"
    elif seconds < 31536000:
        return f"About {int(seconds / 86400)} days"
    elif seconds < 31536000 * 1000:
        return f"About {int(seconds / 31536000)} years"
    elif seconds < 31536000 * 1_000_000:
        return f"About {int(seconds / 31536000):,} years"
    else:
        return "Millions of years+"


# -------------------------------------------------------------------
# GENERATE SHA-256 HASH (learning purposes)
# -------------------------------------------------------------------
def get_hash(password: str) -> str:
    """Shows what the password looks like when hashed."""
    return hashlib.sha256(password.encode()).hexdigest()


# -------------------------------------------------------------------
# MAIN ANALYSIS
# -------------------------------------------------------------------
def analyze_password(password: str) -> dict:
    """Run all checks and return a full analysis."""

    checks = [
        ("Length",          check_length(password)),
        ("Character types", check_character_types(password)),
        ("Common password", check_common_password(password)),
        ("Patterns",        check_patterns(password)),
        ("Repetition",      check_repeated_words(password)),
    ]

    total_points = sum(points for _, (points, _) in checks)
    max_points = 12  # 3 + 4 + 2 + 2 + 1

    # Map score to rating
    percentage = (total_points / max_points) * 100
    if percentage >= 85:
        rating = "STRONG"
        bar_color = "🟩"
    elif percentage >= 60:
        rating = "MODERATE"
        bar_color = "🟨"
    elif percentage >= 35:
        rating = "WEAK"
        bar_color = "🟧"
    else:
        rating = "VERY WEAK"
        bar_color = "🟥"

    # Visual strength bar
    filled = int((percentage / 100) * 20)
    bar = bar_color * filled + "⬜" * (20 - filled)

    return {
        "checks": checks,
        "total_points": total_points,
        "max_points": max_points,
        "percentage": percentage,
        "rating": rating,
        "bar": bar,
        "crack_time": estimate_crack_time(password),
        "sha256": get_hash(password),
    }


def display_results(password: str, result: dict):
    """Pretty-print the analysis."""

    masked = password[0] + "*" * (len(password) - 2) + password[-1]

    print(f"\n{'='*56}")
    print(f"  PASSWORD STRENGTH ANALYSIS")
    print(f"{'='*56}")
    print(f"  Password  : {masked}")
    print(f"  Rating    : {result['rating']}")
    print(f"  Score     : {result['total_points']}/{result['max_points']}")
    print(f"  Strength  : {result['bar']}")
    print(f"  Crack time: {result['crack_time']}")
    print(f"{'='*56}")

    print(f"\n  DETAILED CHECKS:")
    print(f"  {'-'*50}")
    for name, (points, feedback) in result["checks"]:
        icon = "✅" if points >= 2 else "⚠️ " if points == 1 else "❌"
        print(f"  {icon}  {name}: {feedback}")

    print(f"\n  SHA-256 HASH (how it's stored in databases):")
    print(f"  {result['sha256']}")
    print()


# -------------------------------------------------------------------
# INTERACTIVE MODE
# -------------------------------------------------------------------
def interactive_mode():
    """Let the user test multiple passwords in a loop."""
    print("\n  Password Strength Checker — Interactive Mode")
    print("  Type a password to test, or 'quit' to exit.\n")

    while True:
        password = input("  Enter password: ")
        if password.lower() in ("quit", "exit", "q"):
            print("  Goodbye!\n")
            break
        if not password:
            print("  Please enter a password.\n")
            continue

        result = analyze_password(password)
        display_results(password, result)


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker — Cybersecurity Learning Tool",
        epilog='Example: python checker.py "MyP@ssw0rd123!"'
    )
    parser.add_argument(
        "password",
        nargs="?",
        default=None,
        help="Password to analyze (omit to enter interactive mode)"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    if args.password:
        result = analyze_password(args.password)
        display_results(args.password, result)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
