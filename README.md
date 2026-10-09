# Password Strength Checker

A command-line **Cyber Security mini project** written in Python. It analyses a password, gives it a score out of 100, estimates how long an attacker would need to crack it, explains what is wrong, and suggests how to improve it. It can also generate strong random passwords.

> Uses only the Python standard library - no packages to install.

## Features

- Score (0-100) and strength label: *Very Weak, Weak, Moderate, Strong, Very Strong*
- Entropy estimate (in bits) and **estimated offline cracking time**
- Checks length and character variety (lowercase, uppercase, digits, symbols)
- Detects **common passwords** (300-entry list), including "leet speak" tricks like `P@ssw0rd`
- Detects **repeated characters** (`aaaa`), **sequences** (`abcd`, `4321`) and **keyboard patterns** (`qwerty`)
- Gives clear problems found and suggestions to improve
- Hidden password input (`getpass`) so the password is not shown on screen
- **Secure password generator** using Python's `secrets` module
- Unit tests (19 tests)

## Project structure

```
password-strength-checker/
|-- main.py                      # command-line interface
|-- password_checker/
|   |-- __init__.py
|   |-- checker.py               # strength analysis logic
|   |-- generator.py             # secure random password generator
|   `-- common_passwords.txt     # list of common/leaked passwords
|-- tests/
|   `-- test_checker.py          # unit tests
|-- requirements.txt
|-- LICENSE
`-- README.md
```

## Requirements

- Python 3.9 or newer

## Usage

```bash
# Check a password (typing is hidden)
python main.py

# Check a password but show what you type
python main.py --show

# Generate a strong 16-character password and check it
python main.py --generate

# Generate a 24-character password without symbols
python main.py --generate 24 --no-symbols

# Check a password passed as an argument (not recommended - see Security notes)
python main.py -p "MyP@ssw0rd"
```

### Sample output

```
====================================================
 PASSWORD STRENGTH REPORT
====================================================
 Strength   : Very Weak
 Score      : 5/100  [##----------------------------]
 Length     : 11 characters
 Entropy    : ~5.2 bits
 Crack time : instantly (offline, fast hash)
----------------------------------------------------
 Lowercase: yes   Uppercase: no   Digits: yes   Symbols: no
----------------------------------------------------
 Problems found:
   - This is a very common password.
----------------------------------------------------
 Suggestions:
   * Pick something unique; never use a well-known password.
   ...
====================================================
```

## How it works

1. **Character pool** - the checker works out which character types are used (26 lowercase, 26 uppercase, 10 digits, 32 symbols).
2. **Pattern detection** - repeated characters, sequences, keyboard walks and common words are found. Characters that belong to these patterns are *predictable*, so they do not count towards strength.
3. **Entropy** - `entropy = effective_length x log2(pool_size)`, where `effective_length` excludes predictable characters.
4. **Score** - `score = entropy / 80 bits x 100`, capped at 100. Special caps apply:
   - a fully common password is capped at 5,
   - passwords shorter than 8 characters are capped at "Very Weak",
   - passwords shorter than 12 characters cannot be "Very Strong".
5. **Crack time** - on average an attacker finds the password after trying half of all possibilities (`2^entropy / 2`). A rate of 10 billion guesses per second is assumed (fast, unsalted hash cracked offline with GPUs).

| Score  | Label       |
|--------|-------------|
| 0-24   | Very Weak   |
| 25-44  | Weak        |
| 45-69  | Moderate    |
| 70-89  | Strong      |
| 90-100 | Very Strong |

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Security notes

- Passwords are **never stored, logged or sent over the network**. Everything runs locally.
- Avoid `-p/--password`: arguments can be saved in your shell history and visible to other processes. Use the hidden prompt instead.
- Generated passwords use `secrets` (cryptographically secure), not `random`.
- Best practice: use a **password manager**, a **unique password for every site**, and turn on **two-factor authentication**.

## Limitations

- The entropy model assumes characters are chosen randomly. Real attackers use dictionaries, word lists and rules, so the score is only an **estimate** (an upper bound), not a guarantee. For example, a clever disguise of an uncommon word may be rated higher than it deserves.
- The built-in common-password list has only 300 entries. Real-world lists contain millions.

## Future improvements

- Check against the *Have I Been Pwned* breach database using its k-anonymity API
- Larger dictionary and name/date detection
- Graphical interface (Tkinter) or web interface (Flask)
- Passphrase (multi-word) generator

## Author

Yash Dalvi - TY BSc IT

## License

Released under the [MIT License](LICENSE).
