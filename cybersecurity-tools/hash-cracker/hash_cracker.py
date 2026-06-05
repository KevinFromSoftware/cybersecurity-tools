#!/usr/bin/env python3
"""
Hash Cracker - A password hash reverse engineering tool
Author: [Ditt navn]
Description: Identifies hash types and attempts to crack them
             using dictionary and brute-force attacks.

⚠️  FOR EDUCATIONAL USE ONLY — only crack hashes you own or
    have explicit permission to test.
"""

import hashlib
import argparse
import sys
import time
import itertools
import string


# -------------------------------------------------------------------
# HASH IDENTIFICATION — detect which algorithm was used
# -------------------------------------------------------------------
HASH_PATTERNS = {
    32:  "MD5",
    40:  "SHA-1",
    64:  "SHA-256",
    128: "SHA-512",
}


def identify_hash(hash_string: str) -> str:
    """
    Identifies the likely hash type based on length and character set.
    Real-world tools like 'hashid' do this more thoroughly.
    """
    hash_string = hash_string.strip().lower()

    # Check if it's valid hex
    try:
        int(hash_string, 16)
    except ValueError:
        return "Unknown (not a valid hex hash)"

    length = len(hash_string)
    return HASH_PATTERNS.get(length, f"Unknown (length: {length})")


# -------------------------------------------------------------------
# CORE: generate a hash for a given word
# -------------------------------------------------------------------
def hash_word(word: str, algorithm: str) -> str:
    """
    Hashes a word with the specified algorithm.
    This is the core of how cracking works:
      1. Take a guess (word)
      2. Hash it with the same algorithm
      3. Compare to the target hash
      4. If they match → you found the password!
    """
    word_bytes = word.encode("utf-8")

    if algorithm == "MD5":
        return hashlib.md5(word_bytes).hexdigest()
    elif algorithm == "SHA-1":
        return hashlib.sha1(word_bytes).hexdigest()
    elif algorithm == "SHA-256":
        return hashlib.sha256(word_bytes).hexdigest()
    elif algorithm == "SHA-512":
        return hashlib.sha512(word_bytes).hexdigest()
    else:
        return ""


# -------------------------------------------------------------------
# DICTIONARY ATTACK — try every word in a wordlist
# -------------------------------------------------------------------
def dictionary_attack(target_hash: str, algorithm: str, wordlist_path: str) -> str | None:
    """
    Reads a wordlist file line by line and hashes each word.
    If a hash matches the target → password found!

    This is why weak/common passwords are dangerous:
    they exist in public wordlists like 'rockyou.txt'.
    """
    target_hash = target_hash.lower().strip()

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            total_tried = 0

            for line in f:
                word = line.strip()
                if not word:
                    continue

                if hash_word(word, algorithm) == target_hash:
                    return word

                total_tried += 1
                if total_tried % 10000 == 0:
                    print(f"  [ -- ]  Tried {total_tried:,} words...")

    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {wordlist_path}")
        sys.exit(1)

    return None


# -------------------------------------------------------------------
# BRUTE FORCE ATTACK — try all possible combinations
# -------------------------------------------------------------------
def brute_force_attack(
    target_hash: str,
    algorithm: str,
    max_length: int = 4,
    charset: str = "lower"
) -> str | None:
    """
    Generates every possible combination of characters up to max_length.

    This demonstrates WHY longer passwords are more secure:
      - 4 lowercase chars  = 26^4       =     456,976 combos
      - 6 lowercase chars  = 26^6       = 308,915,776 combos
      - 8 mixed chars      = 62^8       = way too many to try!

    We keep max_length small to avoid running forever.
    """
    target_hash = target_hash.lower().strip()

    # Build character set
    chars = ""
    if "lower" in charset:
        chars += string.ascii_lowercase
    if "upper" in charset:
        chars += string.ascii_uppercase
    if "digits" in charset:
        chars += string.digits
    if "special" in charset:
        chars += "!@#$%^&*"
    if charset == "all":
        chars = string.ascii_letters + string.digits + "!@#$%^&*"

    if not chars:
        chars = string.ascii_lowercase

    total_tried = 0

    for length in range(1, max_length + 1):
        print(f"\n  Trying all {len(chars)}^{length} = {len(chars)**length:,} "
              f"combinations of length {length}...")

        for combo in itertools.product(chars, repeat=length):
            word = "".join(combo)

            if hash_word(word, algorithm) == target_hash:
                return word

            total_tried += 1
            if total_tried % 50000 == 0:
                print(f"  [ -- ]  Tried {total_tried:,} combinations...")

    return None


# -------------------------------------------------------------------
# DEMO MODE — create and crack example hashes
# -------------------------------------------------------------------
def run_demo():
    """
    Creates hashes from known passwords, then cracks them.
    Perfect for understanding the concept without needing a wordlist.
    """
    print("\n" + "=" * 56)
    print("  DEMO MODE — Hash Cracker")
    print("=" * 56)

    demo_passwords = ["cat", "dog", "abc", "123", "hi"]

    # Step 1: Create hashes
    print("\n  Step 1: Creating MD5 hashes from known passwords\n")
    demo_hashes = {}
    for pwd in demo_passwords:
        h = hash_word(pwd, "MD5")
        demo_hashes[h] = pwd
        print(f"    '{pwd}' → {h}")

    # Step 2: Now "forget" the passwords and try to crack them
    print("\n  Step 2: Now let's crack them with brute force!\n")

    for target_hash in demo_hashes:
        start = time.time()
        result = brute_force_attack(target_hash, "MD5", max_length=3, charset="lower+digits")
        elapsed = time.time() - start

        if result:
            print(f"\n  ✓ CRACKED: {target_hash[:20]}... → '{result}' "
                  f"({elapsed:.2f}s)")
        else:
            print(f"\n  ✗ Not found: {target_hash[:20]}...")

    print(f"\n{'='*56}")
    print("  Key takeaway: short, simple passwords are cracked instantly.")
    print("  Longer, complex passwords take exponentially longer!")
    print(f"{'='*56}\n")


# -------------------------------------------------------------------
# ARGUMENT PARSING
# -------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Hash Cracker — Educational Password Reverse Engineering Tool",
        epilog="Example: python hash_cracker.py -t 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt"
    )
    parser.add_argument(
        "-t", "--target",
        help="The hash you want to crack"
    )
    parser.add_argument(
        "-a", "--algorithm",
        choices=["MD5", "SHA-1", "SHA-256", "SHA-512"],
        help="Hash algorithm (auto-detected if not specified)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to a wordlist file for dictionary attack"
    )
    parser.add_argument(
        "-b", "--bruteforce",
        type=int,
        metavar="MAX_LEN",
        help="Brute force up to MAX_LEN characters (keep ≤ 5!)"
    )
    parser.add_argument(
        "--charset",
        default="lower",
        help="Character set: lower, upper, digits, special, all (default: lower)"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run demo mode — creates and cracks example hashes"
    )
    parser.add_argument(
        "--hash-text",
        metavar="TEXT",
        help="Hash a text string (useful for creating test hashes)"
    )
    return parser.parse_args()


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    args = parse_args()

    # Quick hash generator
    if args.hash_text:
        algo = args.algorithm or "MD5"
        result = hash_word(args.hash_text, algo)
        print(f"\n  '{args.hash_text}' → [{algo}] → {result}\n")
        return

    # Demo mode
    if args.demo:
        run_demo()
        return

    # Need a target hash for cracking
    if not args.target:
        print("\n  No target hash specified. Try --demo for a quick example!")
        print("  Use -h for help.\n")
        return

    # Identify hash type
    target = args.target.strip().lower()
    detected = identify_hash(target)
    algorithm = args.algorithm or detected

    print(f"\n{'='*56}")
    print(f"  Target    : {target[:40]}...")
    print(f"  Detected  : {detected}")
    print(f"  Algorithm : {algorithm}")
    print(f"{'='*56}")

    if algorithm.startswith("Unknown"):
        print("[ERROR] Could not detect algorithm. Use -a to specify.")
        return

    result = None
    start = time.time()

    # Try dictionary attack first
    if args.wordlist:
        print(f"\n  [1] Dictionary attack using: {args.wordlist}")
        result = dictionary_attack(target, algorithm, args.wordlist)

    # Then try brute force if needed
    if not result and args.bruteforce:
        print(f"\n  [2] Brute force attack (max length: {args.bruteforce})")
        result = brute_force_attack(target, algorithm, args.bruteforce, args.charset)

    elapsed = time.time() - start

    # Results
    print(f"\n{'='*56}")
    if result:
        print(f"  ✓ PASSWORD FOUND: {result}")
    else:
        print(f"  ✗ Password not found")
        if not args.wordlist:
            print(f"    Tip: try with a wordlist (-w wordlist.txt)")
    print(f"  Time: {elapsed:.2f} seconds")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()