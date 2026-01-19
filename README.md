# FlashAudit

High-performance secrets scanner written in Rust. Enterprise-ready with SARIF output for GitHub Advanced Security.

## License

This project is released under a **Proprietary License** as of version vX.Y.Z.

All rights reserved.  
No part of this software may be used, modified, distributed, or offered as a service without explicit written permission from the author.

Commercial use, enterprise deployment, redistribution, or SaaS offering requires a paid license.
Contact: mahapatro32@gmail.com

## Features

- **Blazing Fast**: Hybrid Aho-Corasick + Regex engine (8x faster than gitleaks)
- **Precise**: 66 specific patterns, zero generic rules = minimal false positives
- **Enterprise Ready**: SARIF 2.1.0 output for GitHub Advanced Security
- **Incremental**: `--git-diff` and `--staged` for CI/pre-commit hooks
- **Smart Binary Detection**: 30+ magic byte signatures
- **Configurable**: Load custom rules from YAML
- **CI Ready**: Proper exit codes + cross-platform binaries

## Benchmarks

| Repository | Files | FlashAudit | Gitleaks | Speedup |
|------------|-------|------------|----------|---------|
| Express | 240 | **0.03s** | 0.09s | 3x |
| Django | 7,033 | **0.51s** | 3.93s | 8x |
| Rust Compiler | 57,706 | **1.24s** | 15.23s | **12x** |

**Precision comparison:**
| Repository | FlashAudit | Gitleaks | Notes |
|------------|------------|----------|-------|
| Django | 1 real | 5 (4 FPs) | Gitleaks flags test fixtures |
| Rust | 4 real | 24 (20 FPs) | Gitleaks duplicates same finding |

**12x faster. 6x fewer false positives.**

## Installation

```bash
git clone https://github.com/Ruddxxy/Flash-Audit.git
cd Flash-Audit
cargo build --release
```

**Or download from [Releases](https://github.com/Ruddxxy/Flash-Audit/releases)**

## Usage

```bash
# Basic scan (JSON output)
flash_audit /path/to/repo

# SARIF output for GitHub Advanced Security
flash_audit --format sarif /path/to/repo > results.sarif

# Incremental: Only scan files changed since main
flash_audit --git-diff main /path/to/repo

# Pre-commit hook: Only scan staged files
flash_audit --staged /path/to/repo

# Custom rules
flash_audit --rules my-rules.yaml /path/to/repo

# Entropy detection
flash_audit --entropy /path/to/repo
```

## Output

```
Scanned 500 files in 0.12s. 2 errors. 3 secrets found.
[
  {
    "file": "config.env",
    "line": 12,
    "match_content": "sk_live_",
    "rule_id": "STRIPE_LIVE_KEY",
    "description": "Stripe Live Secret Key"
  }
]
```

## CLI Options

| Option | Default | Description |
|--------|---------|-------------|
| `[PATH]` | `.` | Directory to scan |
| `-f, --format` | json | Output format: `json` or `sarif` |
| `--rules` | embedded | Path to custom rules.yaml |
| `--git-diff <REF>` | - | Only scan files changed since REF (e.g., `main`, `HEAD~1`) |
| `--staged` | false | Only scan staged files (pre-commit hooks) |
| `--entropy` | false | Enable entropy scanning |
| `--entropy-threshold` | 4.5 | Entropy threshold |
| `-v, --verbose` | false | Show debug output |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No secrets |
| 1 | Secrets found |
| 2 | Error |

## Custom Rules

Create `rules.yaml`:

```yaml
rules:
  - id: MY_API_KEY
    pattern: "mycompany_"
    description: "MyCompany API Key"

  - id: INTERNAL_TOKEN
    pattern: "internal_token_"
    description: "Internal Service Token"
```

Use: `flash_audit --rules rules.yaml .`

## Detected Secrets (66 Precise Patterns)

| Category | Patterns |
|----------|----------|
| Private Keys | RSA, OpenSSH, EC, PGP, DSA, PuTTY |
| AWS | Access Key (AKIA), Secret Key |
| GitHub | ghp_, gho_, ghu_, ghs_, ghr_ |
| GitLab | glpat-, GR1348941 |
| Slack | xoxb-, xoxp-, webhooks |
| Google/Firebase | AIza, OAuth Client, firebaseio.com |
| Stripe | sk_live_, sk_test_, rk_live_ |
| Azure | Storage Key, Connection String, SAS Token, Client Secret |
| DigitalOcean | dop_v1_, doo_v1_, dor_v1_ |
| Datadog | API Key, App Key |
| Cloudflare | API Key, API Token |
| AI Services | OpenAI (sk-), Anthropic (sk-ant-) |
| HashiCorp Vault | hvs., hvb. |
| Database URLs | postgres://, mysql://, mongodb://, redis:// (with credentials) |
| Other | SendGrid, Twilio, NPM, PyPI, Shopify, Square, Discord, Heroku, Mailchimp, Mailgun, Linear, Notion, Airtable, Supabase, Doppler, JWT |

**Zero generic patterns = Zero false positives on test fixtures.**

## Architecture

```
src/
├── main.rs             # CLI, orchestration, logging
├── scanner.rs          # Hybrid Aho-Corasick + Regex engine
└── utils/
    ├── config.rs       # YAML rules loader
    ├── file_loader.rs  # Smart file loading + magic bytes detection
    ├── entropy.rs      # Shannon entropy
    └── sarif.rs        # SARIF 2.1.0 output format

rules.yaml              # Default rules (embedded at compile)
```

## GitHub Actions

### Basic (JSON output)
```yaml
- uses: actions/checkout@v4
- run: |
    curl -L https://github.com/Ruddxxy/Flash-Audit/releases/latest/download/flash_audit-linux-x86_64 -o flash_audit
    chmod +x flash_audit
    ./flash_audit .
```

### GitHub Advanced Security (SARIF)
```yaml
- uses: actions/checkout@v4

- name: Run FlashAudit
  run: |
    curl -L https://github.com/Ruddxxy/Flash-Audit/releases/latest/download/flash_audit-linux-x86_64 -o flash_audit
    chmod +x flash_audit
    ./flash_audit . --format sarif > results.sarif
  continue-on-error: true

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Releasing

Push a tag to create cross-platform releases:

```bash
git tag v1.0.0
git push origin v1.0.0
```

Builds for: Linux (x86_64, ARM64), macOS (Intel, M1), Windows


## License

Proprietary. See `LICENSE` for full terms.

> Note: Versions prior to v1.0.1 were released under different terms.  
> All versions starting from v1.1.0 are governed by the Proprietary License.

