Kvault (Key Vault) is console application written in C# that implements a password manager. The program uses a JSON store to persist data and provides a simple command-line interface for managing credentials.

- Vault: The vault stores all user credentials, such as usernames and passwords.

- Encryption Algorithm: AES-GCM (Advanced Encryption Standard with Galois/Counter Mode) is used for encrypting data at rest and in transit.

- Password Generation: A password generator is available to create new passwords, with options for including uppercase letters, lowercase letters, digits, symbols, and allowing or denying ambiguous characters.

- Auto-Unlock and Auto-Clear Clipboard: The app has features for auto-locking the vault after a set period of inactivity (idle timeout) and clearing the clipboard automatically.

- User Interface: The console application displays a simple text-based interface to perform various operations, such as adding or removing credentials, generating passwords, listing all available credentials, searching by service/username/notes/tags, updating password for specific credential IDs, changing the master password, and setting configuration options like clipboard timeout and idle timeout.

Commands:
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