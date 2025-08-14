Kvault (Key Vault) is console application written in C# that implements a password manager. The program uses a JSON store to persist data and provides a simple command-line interface for managing credentials.

- Vault: The vault stores all user credentials, such as usernames and passwords.

- Encryption Algorithm: AES-GCM (Advanced Encryption Standard with Galois/Counter Mode) is used for encrypting data at rest and in transit.

- Password Generation: A password generator is available to create new passwords, with options for including uppercase letters, lowercase letters, digits, symbols, and allowing or denying ambiguous characters.

- Auto-Unlock and Auto-Clear Clipboard: The app has features for auto-locking the vault after a set period of inactivity (idle timeout) and clearing the clipboard automatically.

- User Interface: The console application displays a simple text-based interface to perform various operations, such as adding or removing credentials, generating passwords, listing all available credentials, searching by service/username/notes/tags, updating password for specific credential IDs, changing the master password, and setting configuration options like clipboard timeout and idle timeout.