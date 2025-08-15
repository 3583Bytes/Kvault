# Kvault (Key Vault) Password Manager

A cross‑platform, single‑file password manager written in C# that follows SOLID design principles and uses modern cryptography: **AES‑GCM** per credential and **PBKDF2‑SHA256** for master key derivation. Runs on .NET 6+.

**Platforms:** Windows · macOS · Linux\
**Store:** Local JSON (no server)\
**Security:** AEAD (per‑record), auto‑lock on idle, clipboard auto‑clear

---

## ✨ Features

- **Per‑record encryption (AES‑GCM)** with random 96‑bit nonces and **AAD** binding to `service + username`.
- **KDF:** PBKDF2‑SHA256 with random salt and tunable iterations (default `200_000`).
- **Master verification:** HMAC(masterHmacKey, "vault") stored in vault metadata.
- **Auto‑lock** on inactivity (default **5 minutes**, configurable & persisted).
- **Clipboard auto‑clear** (default **20 seconds**, configurable & persisted).
- **Strong password generator** (crypto‑secure, unbiased sampling, guaranteed class mix).
- **Search** across service/username/notes/tags.
- **Tags**: add/remove/set/list tags per credential; filter with `list --tag` and search.
- **Atomic, durable saves** with `.tmp` replace and rolling `.bak` backup.
- **Simple local storage** under a `data/` folder next to the executable.

> **Note:** Metadata fields (service, username, notes, tags) are currently plaintext for speed/UX. See **Security Notes** for hardening options.

---

## 🧰 Prerequisites

- **.NET 6+ SDK** (or .NET 7/8): [https://dotnet.microsoft.com/download](https://dotnet.microsoft.com/download)
- **Clipboard helpers** (Linux only):
  - Install either `xclip` or `xsel` (macOS uses `pbcopy`; Windows uses `clip`).

```bash
# Ubuntu/Debian (choose one)
sudo apt-get install xclip
# or
sudo apt-get install xsel
```

---

## 🚀 Quick Start

```bash
# 1) Build & run
dotnet run --project Kvault
```

On first run, the app will create a `data/` folder next to the executable, including:

- `data/vault.json` — the encrypted credentials
- `data/config.json` — persisted app settings

You’ll be prompted to **create a master password**. After that, use `unlock` to begin.

---

## 💻 Usage

Type `help` in the REPL to see all commands:

```
 help                                 Show this help

  unlock                               Unlock the vault
  lock                                 Lock the vault

  list [--tag <tag>]                   List passwords (optionally filter by tag)
  add <service> <user> [notes]         Add a password (leave password empty
                                       to auto-generate)
  get <service> <user> [--show]        Copy password to clipboard (default).
                                       Add --show to print
  copy <service> <user>                Explicitly copy password to clipboard
  gen [len] [flags]                    Generate a password (copies by default).
                                       Flags: --show, --no-upper, --no-lower,
                                       --no-digits, --no-symbols,
                                       --allow-ambiguous
  search <term>                        Search service/username/notes/tags
  update <id>                          Update password by credential id
                                       (leave empty to auto-generate)
  remove <id>                          Remove credential by id

  tag <id> add <tag>                   Add one tag to a credential
  change-master                        Change master password (re-encrypts all)

  set clipboard-timeout <seconds|off>  Configure clipboard auto-clear
  set idle-timeout <minutes|off>       Configure auto-lock timeout

  exit|quit|bye                        Exit app
```

### Common flows

**Initialize & unlock**

```
# first run initializes; then
unlock
```

**Add a credential with tags; auto-generate password**

```
add github.com alice "Personal account" --tags personal,dev
# When prompted for password, just press Enter → auto-generates, copies to clipboard, auto-clears later.
```

**Get or copy a password**

```
get github.com alice        # copies to clipboard
get github.com alice --show # prints to console
copy github.com alice       # explicitly copy
```

**Search & list by tag**

```
search github
list --tag work
```

**Manage tags**

```
tag <id> list
tag <id> add work,infra
tag <id> remove personal
tag <id> set prod,critical
```

**Change the master password**

```
change-master
```

---

## ⚙️ Configuration (`data/config.json`)

Settings persist across runs and can be edited via the `set` command or by hand:

```jsonc
{
  "ClipboardTimeoutSeconds": 20,      // 0 disables clipboard auto-clear
  "IdleTimeoutMinutes": 5,            // 0 disables auto-lock
  "GeneratorLength": 20,              // 8..128
  "GeneratorUpper": true,
  "GeneratorLower": true,
  "GeneratorDigits": true,
  "GeneratorSymbols": true,
  "GeneratorExcludeAmbiguous": true   // exclude look‑alike chars like Il1O0| etc.
}
```

**Tweak at runtime**

```
set clipboard-timeout 45     # clear clipboard 45s after copy
set clipboard-timeout off    # disable clipboard clear
set idle-timeout 2           # auto-lock after 2 minutes
set gen length 32            # change password generator defaults
set gen symbols off          # no symbols by default
set gen ambiguous allow      # include look‑alike chars
```

---

## 🗃️ Data & Layout

```
/your-app-root
 ├─ data/
 │   ├─ vault.json        # encrypted credentials (JSON)
 │   ├─ vault.json.bak    # previous backup (atomic replace)
 │   └─ config.json       # persisted settings
 └─ Program.cs            # the application (single file)
```

- **Atomic save**: writes to `vault.json.tmp` and replaces, producing `vault.json.bak`.
- **Per‑record encryption**: every credential has its own nonce + ciphertext (with tag appended).

---

## 🔐 Security Notes

- **AEAD**: AES‑GCM with 12‑byte random nonces. AAD is `"<service>\u0001<username>"`, binding ciphertext to metadata.
- **KDF**: PBKDF2‑SHA256 with random salt; iterations are stored in metadata; master verification via HMAC.
- **In‑memory handling**: plaintext password bytes are zeroed after use; clipboard is cleared automatically after a timeout.
- **Metadata visibility**: service, username, notes, and tags are plaintext within the JSON. If the file is stolen, this metadata is visible. You can harden by encrypting these fields too (future enhancement).
- **Permissions**: consider restricting file ACLs (e.g., `chmod 600 data/vault.json` on Unix).

### Planned/optional hardening

- Argon2id KDF option, vault‑level MAC for tamper detection, encrypted metadata, breach checks, TOTP secrets, hardware‑backed key wrapping.

---

## 🧱 Architecture (SOLID at a glance)

- **Interfaces**: `IVaultStore`, `IKeyDerivationService`, `IEncryptionService`, `ICredentialRepository`, `IVaultSession`, `IClipboardService`, `IPasswordGenerator`, `IConfigStore`.
- **Implementations**: `FileVaultStore`, `Pbkdf2KeyDerivationService`, `AesGcmEncryptionService`, `JsonCredentialRepository`, `VaultSession`, `CrossPlatformClipboardService`, `CryptoPasswordGenerator`, `FileConfigStore`.
- **App orchestration**: `App` composes dependencies; `Program` wires paths (`data/vault.json`, `data/config.json`).

Swap implementations or add new ones without touching call sites (e.g., add `Argon2KeyDerivationService`).

---

## 🧪 Testing ideas

- Unit tests for: encryption round‑trips, KDF derivation, command parsing, repository operations, and clipboard/idle timers.

---

## 🐛 Troubleshooting

- **Linux clipboard**: install `xclip` or `xsel`. If both present, `xclip` is tried first.
- **Auto‑lock/clipboard timers**: set to `off` to disable, or adjust via `set` commands.
- **Clean rebuild**: `dotnet clean && dotnet build`.

---

## 📄 License

MIT

---

## 🙌 Acknowledgements

- .NET `System.Security.Cryptography` for AES‑GCM and PBKDF2.
- Community tools: `pbcopy` (macOS), `clip` (Windows), `xclip`/`xsel` (Linux).

---

## 📬 Feedback & Contributions

Issues and PRs are welcome. Ideas: Argon2id KDF, encrypted metadata, vault MAC, TOTP, breach checks, and health reports.

