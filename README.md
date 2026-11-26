# Password Strength Checker

![CI](https://github.com/DayrillMuller/password-strength-checker/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/pytest-120%20passed-2EA44F?logo=pytest&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)
![CLI](https://img.shields.io/badge/CLI-Rich-ff69b4)

A modular, production-grade CLI Password Strength Checker written in Python. It combines effective bit-entropy analysis, passphrase recognition, leet-speak normalization, keyboard walk detection, and optional privacy-safe breach checking with a polished Rich terminal UI and scriptable JSON output.

---

## Features

- **Typed Security Engine (`checker.py`)** — Pure evaluation logic returning a frozen `PasswordReport` dataclass (`score`, `rating`, `entropy_bits`, `is_breached`, `breach_count`, `is_passphrase`, `suggestions`, and per-rule `checks`).
- **Entropy & Passphrase Awareness** — Computes effective bit entropy from character pool size and structure, and recognizes 16+ character multi-word passphrases without over-penalizing missing special symbols.
- **Common Password & Leet-Speak Detection** — Normalizes substitutions (`@`→`a`, `0`→`o`, `$`→`s`, `1`→`i`/`l`, `3`→`e`, `!`→`i`) and trailing digits/symbols to catch weak variants like `P@ssw0rd!` and `P@ssw0rd123`.
- **Pattern & Keyboard Walk Detection** — Penalizes repeated characters (`aaa`, `1111`), sequential runs (`1234`, `abcd`), and forward/reverse horizontal and diagonal keyboard walks (`qwerty`, `asdfgh`, `zxcvbn`, `1qaz2wsx`).
- **Optional HIBP Breach Lookup** — Queries the Have I Been Pwned k-anonymity range API with a 3-second timeout and graceful offline fallback.
- **Rich Terminal UI & Automation Modes (`main.py`)** — Masked `getpass` input by default, color-coded strength meter, breakdown table, suggestion panels, `--visible`, `--breach-check`, `--json`, and `stdin` piping.
- **Robust Input Handling** — Safely handles empty/whitespace inputs, 128-character maximum length capping, full Unicode/emoji passwords, `EOFError`, and `Ctrl+C`.

---

## Installation

Requires **Python 3.10+**.

Clone the repository and install in editable mode:

```bash
git clone https://github.com/DayrillMuller/password-strength-checker.git
cd password-strength-checker
pip install -e .
```

To include development and testing tools (`pytest`, `ruff`, `mypy`):

```bash
pip install -e ".[dev]"
```

---

## Usage & CLI Flags

### Interactive Mode (Default — Masked Input)

```bash
python main.py
```

*(If installed via `pip install -e .`, you can also run `password-checker` directly.)*

### CLI Flags

| Flag | Description |
| :--- | :--- |
| `--visible` | Show typed characters during interactive entry instead of masking with `getpass`. |
| `--breach-check` | Enable privacy-safe Have I Been Pwned k-anonymity breach lookup. |
| `--json` | Emit machine-readable JSON output for scripts and CI pipelines. |

### Command Examples

```bash
# Interactive masked prompt (default)
python main.py

# Interactive mode with visible input and breach checking
python main.py --visible --breach-check

# Pipe a password from stdin and output formatted Rich panels
echo "P@ssw0rd123" | python main.py

# Pipe a password from stdin for machine-readable JSON output
echo "Correct Horse Battery 99!" | python main.py --json

# Pipe a password with optional breach check and JSON output
echo "Correct Horse Battery 99!" | python main.py --breach-check --json
```

In interactive mode, type `exit` or `quit` (or press `Ctrl+C`) to leave cleanly.

---

## Sample Output

### Rich Terminal Output

```text
┌───────────────────────────── Password Analysis ─────────────────────────────┐
│ Strength      [████░░░░░░░░░░░░░░░░░░░░░░░░░░]  15/100  Weak                │
│ Entropy       10.00 bits (Low)                                              │
│ Breach Check  Skipped (use --breach-check)                                  │
└─────────────────────────────────────────────────────────────────────────────┘
           Security Breakdown
 Rule                             Status
─────────────────────────────────────────
 Minimum length (8+ chars)          PASS
 Recommended length (12+ chars)     INFO
 Strong length (16+ chars)          INFO
 Lowercase letters                  PASS
 Uppercase letters                  PASS
 Digits (0-9)                       PASS
 Special characters                 PASS
 Common / leet-speak check          FAIL
 No repeated characters             PASS
 No sequential runs                 PASS
 No keyboard walks                  PASS
 No leading/trailing spaces         PASS
┌────────────────────────── Improvement Suggestions ──────────────────────────┐
│ • Increase length to at least 12 characters for stronger security.          │
│ • Avoid commonly used passwords or predictable leet-speak variants (e.g.,   │
│ 'P@ssw0rd!').                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

### JSON Output (`--json`)

```json
{
  "score": 100,
  "rating": "Very Strong",
  "entropy_bits": 164.25,
  "is_breached": null,
  "breach_count": null,
  "is_passphrase": true,
  "suggestions": [],
  "checks": {
    "valid_input": true,
    "min_length": true,
    "recommended_length": true,
    "strong_length": true,
    "within_max_length": true,
    "has_lowercase": true,
    "has_uppercase": true,
    "has_digit": true,
    "has_special": true,
    "passphrase": true,
    "not_common": true,
    "no_repeated_chars": true,
    "no_sequential_runs": true,
    "no_keyboard_walks": true,
    "no_edge_whitespace": true
  }
}
```

---

## Privacy & Security

- **100% Local Evaluation:** All password scoring, entropy calculation, leet-speak normalization, and pattern detection execute strictly locally in memory. Passwords are never written to disk, logged, or transmitted.
- **SHA-1 k-Anonymity Breach Check:** When `--breach-check` is explicitly enabled, the tool hashes the password locally with SHA-1 and sends **only the first 5 hex characters** of the hash to `api.pwnedpasswords.com/range/{prefix}` (with `Add-Padding: true` enabled). Matching against returned hash suffixes happens entirely on your machine—neither your plaintext password nor its full hash ever leaves your device. If the network is unavailable or times out (3s limit), the check falls back gracefully without failing.

---

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI (pytest on Python 3.11 & 3.12)
├── checker.py              # Core password evaluation engine (pure logic)
├── main.py                 # Rich CLI & stdin/JSON entry point
├── test_checker.py         # Automated pytest unit test suite (120 tests)
├── pyproject.toml          # Packaging, dependencies & tool config
├── LICENSE                 # MIT License
└── README.md               # Documentation
```

---

## Running Tests

```bash
pytest -v
```

Optional static checks (if installed):

```bash
ruff check .
mypy checker.py main.py test_checker.py
```

---

## License

This project is licensed under the [MIT License](LICENSE).
