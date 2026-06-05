# 🔐 Password Strength Checker

A password analysis tool that rates strength, detects common weaknesses, and estimates crack time — built as a cybersecurity learning project.

## What it checks

- **Length** — is it long enough? (12+ recommended, 16+ ideal)
- **Character types** — lowercase, uppercase, digits, special characters
- **Common passwords** — compared against top 50 from real data breaches
- **Keyboard patterns** — detects walks like `qwerty`, `1234`, `asdfgh`
- **Repetition** — catches passwords like `catcat` or `aaaa`
- **Crack time estimate** — based on 10 billion guesses/second (modern GPU cluster)
- **SHA-256 hash** — shows how the password looks when stored in a database

## Usage

```bash
# Analyze a single password
python3 checker.py "MyP@ssw0rd123!"

# Interactive mode — test multiple passwords
python3 checker.py
```

## Example output

```
========================================================
  PASSWORD STRENGTH ANALYSIS
========================================================
  Password  : q****y
  Rating    : VERY WEAK
  Score     : 2/12
  Strength  : 🟥🟥🟥⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜
  Crack time: Less than a second
========================================================

  DETAILED CHECKS:
  --------------------------------------------------
  ❌  Length: Too short (6 characters) — minimum 8, aim for 12+
  ⚠️  Character types: Missing: UPPERCASE letters, digits, special characters
  ❌  Common password: Top 50 most common — instantly crackable!
  ❌  Patterns: Contains keyboard pattern 'qwerty'
```

## How it works

The checker runs five independent tests, each awarding 0–4 points. The total is mapped to a rating:

| Score | Rating |
|---|---|
| 85–100% | STRONG |
| 60–84% | MODERATE |
| 35–59% | WEAK |
| 0–34% | VERY WEAK |

Crack time is estimated using: `(charset_size ^ password_length) / guesses_per_second`, where guesses per second is set to 10 billion (a realistic figure for a modern GPU cluster running hashcat).

## Concepts covered

- Password security policies and why they exist
- Brute force attacks and how character space affects crack time
- Hashing with SHA-256 (how passwords are stored, not in plaintext)
- Common attack vectors: dictionary attacks, keyboard pattern detection
- Regular expressions (`re` module) for pattern matching
- Python `hashlib` for cryptographic hashing

## Ideas for extending this project

- [ ] Check against the Have I Been Pwned API (real breach database)
- [ ] Add entropy calculation (bits of randomness)
- [ ] Generate strong random passwords as suggestions
- [ ] Add a simple GUI with `tkinter`
- [ ] Support reading a list of passwords from a file

## Requirements

Python 3.7+ — no external libraries needed.

---

*Part of my cybersecurity learning journey at Noroff University College.*
