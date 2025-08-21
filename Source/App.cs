using System.Security.Cryptography;
using System.Text;

namespace KVault
{

    public sealed class App
    {
        private readonly string _vaultPath;
        private readonly string _configPath;
        private readonly IConfigStore _configStore;
        private AppConfig _config;
        private readonly IVaultStore _store;
        private readonly IKeyDerivationService _kdf;
        private readonly IEncryptionService _enc;
        private readonly IClipboardService _clipboard;
        private readonly IPasswordGenerator _passwordGenerator;
        private TimeSpan _idleTimeout;
        private readonly System.Threading.Timer _idleTimer;
        private readonly object _idleSync = new();
        private readonly TimeSpan _clipboardClearDefault = TimeSpan.FromSeconds(20);
        private TimeSpan _clipboardClearAfter;
        private readonly System.Threading.Timer _clipboardTimer;
        private VaultData _vault;
        private readonly VaultSession _session;

        /// <summary>
        /// Wires up services, loads vault and config, and initializes timers.
        /// </summary>

        public App(string vaultPath, string configPath)
        {
            _vaultPath = vaultPath;
            _store = new FileVaultStore();
            _vault = _store.LoadOrCreate(_vaultPath);
            _kdf = new Pbkdf2KeyDerivationService();
            _enc = new AesGcmEncryptionService();
            _clipboard = new CrossPlatformClipboardService();
            _passwordGenerator = new CryptoPasswordGenerator();
            _session = new VaultSession(_vaultPath, _vault, _store, _kdf);
            _configPath = configPath;
            _configStore = new FileConfigStore();
            _config = _configStore.LoadOrCreate(_configPath);
            _idleTimeout = _config.IdleTimeoutMinutes > 0 ? TimeSpan.FromMinutes(_config.IdleTimeoutMinutes) : TimeSpan.Zero;
            _clipboardClearAfter = _config.ClipboardTimeoutSeconds > 0 ? TimeSpan.FromSeconds(_config.ClipboardTimeoutSeconds) : TimeSpan.Zero;
            _idleTimer = new Timer(OnIdleTimeout, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _clipboardTimer = new Timer(OnClipboardClear, null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        /// <summary>
        /// Application entry for the REPL loop. Parses commands and dispatches handlers.
        /// </summary>
        public void Run()
        {
            this.WriteHeader();
            EnsureInitialized();
            Console.WriteLine("Type 'help' to see available commands.\n");

            while (true)
            {
                Console.Write("pm> ");
                var input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) continue;
                var parts = SplitArgs(input);
                ResetIdleTimer();
                var cmd = parts[0].ToLowerInvariant();

                try
                {
                    switch (cmd)
                    {
                        case "help": PrintHelpDetailed(); break;
                        case "unlock": CmdUnlock(); break;
                        case "lock": CmdLock(); break;
                        case "add": CmdAdd(parts); break;
                        case "get": CmdGet(parts); break;
                        case "copy": CmdCopy(parts); break;
                        case "gen": CmdGen(parts); break;
                        case "list": CmdList(parts); break;
                        case "ls": CmdList(parts); break;
                        case "search": CmdSearch(parts); break;
                        case "update": CmdUpdate(parts); break;
                        case "remove": CmdRemove(parts); break;
                        case "change-master": CmdChangeMaster(); break;
                        case "set": CmdSet(parts); break;
                        case "tag": CmdTag(parts); break;
                        case "exit": case "quit": case "bye": return;
                        default: Console.WriteLine("Unknown command. Type 'help'."); break;
                    }
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"Error: {ex.Message}");
                    Console.ResetColor();
                }
            }
        }

        /// <summary>
        /// Ensures the vault has a master password set; prompts to initialize if not present.
        /// </summary>
        private void EnsureInitialized()
        {
            if (_vault.Metadata.VerificationHmac is { Length: > 0 }) return;
            Console.WriteLine("No master password set. Initializing a new vault...");
            var master = PromptHidden("Create master password: ");
            var confirm = PromptHidden("Confirm master password: ");
            if (master != confirm) throw new InvalidOperationException("Passwords do not match.");
            _session.InitializeVault(master);
            Console.WriteLine("Vault initialized. Use 'unlock' to begin.");
        }

        /// <summary>
        /// Unlocks the vault by deriving the master key from the provided password.
        /// </summary>
        private void CmdUnlock()
        {
            if (_session.IsUnlocked) { Console.WriteLine("Already unlocked."); return; }
            var master = PromptHidden("Master password: ");
            _session.Unlock(master);
            ResetIdleTimer();

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Unlocked.");
            Console.ResetColor();
        }

        /// <summary>
        /// Locks the vault and stops the idle timer.
        /// </summary>
        private void CmdLock()
        {
            StopIdleTimer();
            _session.Lock();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Locked.");
            Console.ResetColor();
        }

        /// <summary>
        /// Adds a credential; will auto-generate a password if input is empty.
        /// </summary>
        private void CmdAdd(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 3)
            {
                Console.WriteLine("Usage: add <service> <username> [notes]");
                return;
            }
            var service = args[1];
            var username = args[2];
            var notes = args.Count >= 4 ? string.Join(' ', args.Skip(3)) : null;
            var pwd = PromptHidden("Password (leave empty to auto-generate): ");

            if (string.IsNullOrEmpty(pwd))
            {
                pwd = _passwordGenerator.Generate(_config.GeneratorLength, _config.GeneratorUpper, _config.GeneratorLower, _config.GeneratorDigits, _config.GeneratorSymbols, _config.GeneratorExcludeAmbiguous);
                _clipboard.SetText(pwd);
                Console.WriteLine("Generated a strong password and copied to clipboard.");
            }

            using var repo = CreateRepository();
            var cred = repo.Add(service, username, notes, pwd);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Added: {cred.Id} ({cred.Service}/{cred.Username})");
            Console.ResetColor();
        }

        /// <summary>
        /// Adds a tag to credential's entry; requires the credential ID and "add" action.
        /// </summary>
        private void CmdTag(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 4 || !args[2].Equals("add", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("Usage: tag <credential-id> add <tag>");
                return;
            }

            if (!Guid.TryParse(args[1], out var id))
            {
                Console.WriteLine("Invalid id.");
                return;
            }

            var toAdd = args[3]
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            using var repo = CreateRepository();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(repo.AddTags(id, toAdd) ? "Tags added." : "Not found.");
            Console.ResetColor();
        }

        // <summary>
        /// Retrieves a credential's password; copies to clipboard by default or prints with --show.
        /// </summary>
        private void CmdGet(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 3)
            {
                Console.WriteLine("Usage: get <service> <username> [--show|-s]");
                return;
            }
            var service = args[1];
            var username = args[2];
            bool show = args.Skip(3).Any(a => a.Equals("--show", StringComparison.OrdinalIgnoreCase) || a.Equals("-s", StringComparison.OrdinalIgnoreCase));

            using var repo = CreateRepository();
            var cred = repo.FindByService(service, username);
            if (cred == null) { Console.WriteLine("Not found."); return; }

            var aad = Encoding.UTF8.GetBytes($"{cred.Service}{cred.Username}");
            var plaintext = _enc.Decrypt(cred.Nonce, cred.Ciphertext, _session.CurrentKey!.AesKey, aad);
            try
            {
                var passwordText = Encoding.UTF8.GetString(plaintext);
                if (show)
                {
                    Console.WriteLine($"Password: {passwordText}");
                }
                else
                {
                    _clipboard.SetText(passwordText);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Password copied to clipboard.");
                    Console.ResetColor();
                    ScheduleClipboardClear();
                }
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }

        /// <summary>
        /// Copies a credential's password to the clipboard.
        /// </summary>
        private void CmdCopy(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 3)
            {
                Console.WriteLine("Usage: copy <service> <username>");
                return;
            }
            var service = args[1];
            var username = args[2];
            using var repo = CreateRepository();
            var cred = repo.FindByService(service, username);
            if (cred == null) { Console.WriteLine("Not found."); return; }

            var aad = Encoding.UTF8.GetBytes($"{cred.Service}{cred.Username}");
            var plaintext = _enc.Decrypt(cred.Nonce, cred.Ciphertext, _session.CurrentKey!.AesKey, aad);
            try
            {
                var passwordText = Encoding.UTF8.GetString(plaintext);
                _clipboard.SetText(passwordText);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Password copied to clipboard.");
                Console.ResetColor();
                ScheduleClipboardClear();
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }

        /// <summary>
        /// Generates a password using defaults (overridable by flags); copies unless --show.
        /// </summary>
        private void CmdGen(IReadOnlyList<string> args)
        {
            int length = _config.GeneratorLength;
            bool show = args.Skip(1).Any(a => a.Equals("--show", StringComparison.OrdinalIgnoreCase) || a.Equals("-s", StringComparison.OrdinalIgnoreCase));
            bool includeUpper = _config.GeneratorUpper, includeLower = _config.GeneratorLower, includeDigits = _config.GeneratorDigits, includeSymbols = _config.GeneratorSymbols, excludeAmbiguous = _config.GeneratorExcludeAmbiguous;

            foreach (var a in args.Skip(1))
            {
                if (int.TryParse(a, out var n)) { length = Math.Clamp(n, 8, 128); continue; }
                switch (a.ToLowerInvariant())
                {
                    case "--show": case "-s": break;
                    case "--no-upper": includeUpper = false; break;
                    case "--no-lower": includeLower = false; break;
                    case "--no-digits": includeDigits = false; break;
                    case "--no-symbols": includeSymbols = false; break;
                    case "--allow-ambiguous": excludeAmbiguous = false; break;
                }
            }
            if (!includeUpper && !includeLower && !includeDigits && !includeSymbols)
            {
                Console.WriteLine("At least one character class must be enabled.");
                return;
            }
            var pwd = _passwordGenerator.Generate(length, includeUpper, includeLower, includeDigits, includeSymbols, excludeAmbiguous);
            if (show)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"Generated: {pwd}");
                Console.ResetColor();
            }
            else
            {
                _clipboard.SetText(pwd);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Generated password copied to clipboard.");
                Console.ResetColor();
                ScheduleClipboardClear();
            }
        }

        /// <summary>
        /// Case-insensitive search over service, username, notes, and tags.
        /// </summary>
        private void CmdSearch(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 2)
            {
                Console.WriteLine("Usage: search <term>");
                return;
            }
            var term = string.Join(' ', args.Skip(1));
            using var repo = CreateRepository();
            var results = repo.List().Where(c =>
                (!string.IsNullOrEmpty(c.Service) && c.Service.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(c.Username) && c.Username.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
                (!string.IsNullOrEmpty(c.Notes) && c.Notes.Contains(term, StringComparison.OrdinalIgnoreCase)) ||
                (c.Tags != null && c.Tags.Any(t => t != null && t.Contains(term, StringComparison.OrdinalIgnoreCase)))
            ).ToList();

            if (results.Count == 0) { Console.WriteLine("No matches."); return; }

            int width = GetSafeWindowWidth();
            int labelW = 10; // label column width
            string sep = new string('─', Math.Min(width, 120));

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Credentials ({results.Count})");
            Console.ResetColor();
            Console.WriteLine(sep);

            foreach (var c in results)
            {
                var tags = (c.Tags == null || c.Tags.Count == 0) ? "-" : string.Join(',', c.Tags);

                PrintField("ID", c.Id.ToString(), labelW, width, ConsoleColor.Yellow);
                PrintField("Service", c.Service, labelW, width, ConsoleColor.Cyan);
                PrintField("Username", c.Username, labelW, width, ConsoleColor.White);
                PrintField("Tags", tags, labelW, width, ConsoleColor.Green);
                PrintField("Updated", c.UpdatedAtUtc.ToLocalTime()
                                                       .ToString("yyyy-MM-dd HH:mm"), labelW, width, ConsoleColor.DarkGray);
                if (!string.IsNullOrWhiteSpace(c.Notes))
                    PrintField("Notes", c.Notes!, labelW, width, ConsoleColor.Gray);

                Console.WriteLine(sep);
            }
        }

        /// <summary>
        /// Tags credentials; can filter by an exact tag (case-insensitive).
        /// </summary>
        /// <summary>
        /// Adds, removes, sets, or lists tags for a credential.
        /// Usage:
        ///   tag <id> list
        ///   tag <id> add <tags...>
        ///   tag <id> remove <tags...>
        ///   tag <id> set <tags...>
        /// Tags may be comma- or space-separated. Case-insensitive; stored in lowercase.
        /// </summary>
        private void CmdTags(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 3)
            {
                Console.WriteLine("Usage: tag <id> <list|add|remove|set> [tags...]");
                return;
            }
            if (!Guid.TryParse(args[1], out var id)) { Console.WriteLine("Invalid id."); return; }
            var action = args[2].ToLowerInvariant();

            using var repo = CreateRepository();

            if (action == "list")
            {
                var cred = repo.List().FirstOrDefault(c => c.Id == id);
                if (cred == null) { Console.WriteLine("Not found."); return; }
                var tags = (cred.Tags == null || cred.Tags.Count == 0) ? "-" : string.Join(',', cred.Tags);
                Console.WriteLine($"Tags: {tags}");
                return;
            }

            if (args.Count < 4) { Console.WriteLine("Specify tags (comma or space separated)."); return; }
            var tokens = string.Join(' ', args.Skip(3))
                .Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(t => t.ToLowerInvariant());

            bool ok = action switch
            {
                "add" => repo.AddTags(id, tokens),
                "remove" => repo.RemoveTags(id, tokens),
                "set" => repo.SetTags(id, tokens),
                _ => false
            };

            Console.WriteLine(ok ? "Tags updated." : "Not found.");
        }

        static void PrintField(string label, string? value, int labelW, int totalWidth, ConsoleColor valueColor)
        {
            value ??= "-";
            int max = Math.Max(20, totalWidth - labelW - 3); // space for value, respecting label column
            var lines = Wrap(value, max);

            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write(label.PadRight(labelW));
            Console.ResetColor();
            Console.ForegroundColor = valueColor;
            Console.WriteLine(" " + lines[0]);
            Console.ResetColor();

            for (int i = 1; i < lines.Count; i++)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write(new string(' ', labelW));
                Console.ResetColor();
                Console.ForegroundColor = valueColor;
                Console.WriteLine(" " + lines[i]);
                Console.ResetColor();
            }
        }

        static List<string> Wrap(string text, int maxWidth)
        {
            // Simple word-wrapping without truncation
            var words = text.Split(' ', StringSplitOptions.None);
            var lines = new List<string>();
            var sb = new StringBuilder();

            foreach (var w in words)
            {
                // if a single word is longer than maxWidth, hard-split it
                if (w.Length > maxWidth)
                {
                    if (sb.Length > 0) { lines.Add(sb.ToString()); sb.Clear(); }
                    int idx = 0;
                    while (idx < w.Length)
                    {
                        int take = Math.Min(maxWidth, w.Length - idx);
                        lines.Add(w.Substring(idx, take));
                        idx += take;
                    }
                    continue;
                }

                int addLen = (sb.Length == 0 ? 0 : 1) + w.Length;
                if (sb.Length + addLen > maxWidth)
                {
                    lines.Add(sb.ToString());
                    sb.Clear();
                }
                if (sb.Length > 0) sb.Append(' ');
                sb.Append(w);
            }

            if (sb.Length > 0) lines.Add(sb.ToString());
            if (lines.Count == 0) lines.Add(string.Empty);
            return lines;
        }

        static int GetSafeWindowWidth()
        {
            try { return Console.WindowWidth; }
            catch { return 100; } // Fallback for redirected output / non-TTY
        }

        /// <summary>
        /// List credentials stored in vault
        /// </summary>
        private void CmdList(IReadOnlyList<string> args)
        {
            RequireUnlocked();

            // parse optional tag filter (unchanged)
            string? tagFilter = null;
            for (int i = 1; i < args.Count; i++)
            {
                var a = args[i];
                if (a.Equals("--tag", StringComparison.OrdinalIgnoreCase) || a.Equals("-t", StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 >= args.Count) { Console.WriteLine("Usage: list [--tag <tag>]"); return; }
                    tagFilter = args[++i];
                }
            }

            using var repo = CreateRepository();
            var rows = repo.List();
            if (!string.IsNullOrEmpty(tagFilter))
            {
                rows = rows.Where(c => c.Tags != null && c.Tags.Any(t => string.Equals(t, tagFilter, StringComparison.OrdinalIgnoreCase)));
            }
            var list = rows.ToList();
            if (list.Count == 0) { Console.WriteLine("(empty)"); return; }

            int width = GetSafeWindowWidth();
            int labelW = 10; // label column width
            string sep = new string('─', Math.Min(width, 120));

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"Credentials ({list.Count})");
            Console.ResetColor();
            Console.WriteLine(sep);

            foreach (var c in list)
            {
                var tags = (c.Tags == null || c.Tags.Count == 0) ? "-" : string.Join(',', c.Tags);

                PrintField("ID", c.Id.ToString(), labelW, width, ConsoleColor.Yellow);
                PrintField("Service", c.Service, labelW, width, ConsoleColor.Cyan);
                PrintField("Username", c.Username, labelW, width, ConsoleColor.White);
                PrintField("Tags", tags, labelW, width, ConsoleColor.Green);
                PrintField("Updated", c.UpdatedAtUtc.ToLocalTime()
                                                       .ToString("yyyy-MM-dd HH:mm"), labelW, width, ConsoleColor.DarkGray);
                if (!string.IsNullOrWhiteSpace(c.Notes))
                    PrintField("Notes", c.Notes!, labelW, width, ConsoleColor.Gray);

                Console.WriteLine(sep);
            }

        }


        /// <summary>
        /// Updates the password for a credential (auto-generates if input empty).
        /// </summary>
        private void CmdUpdate(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 2)
            {
                Console.WriteLine("Usage: update <credential-id>");
                return;
            }
            if (!Guid.TryParse(args[1], out var id)) { Console.WriteLine("Invalid id."); return; }
            var pwd = PromptHidden("New password (leave empty to auto-generate): ");
            if (string.IsNullOrEmpty(pwd))
            {
                pwd = _passwordGenerator.Generate(_config.GeneratorLength, _config.GeneratorUpper, _config.GeneratorLower, _config.GeneratorDigits, _config.GeneratorSymbols, _config.GeneratorExcludeAmbiguous);
                _clipboard.SetText(pwd);
                Console.WriteLine("Generated and copied new password to clipboard.");
                ScheduleClipboardClear();
            }
            using var repo = CreateRepository();
            if (repo.UpdatePassword(id, pwd)) Console.WriteLine("Updated."); else Console.WriteLine("Not found.");
        }

        /// <summary>
        /// Deletes a credential by id after a confirmation prompt.
        /// </summary>
        private void CmdRemove(IReadOnlyList<string> args)
        {
            RequireUnlocked();
            if (args.Count < 2)
            {
                Console.WriteLine("Usage: remove <credential-id>");
                return;
            }
            if (!Guid.TryParse(args[1], out var id)) { Console.WriteLine("Invalid id."); return; }
            using var repo = CreateRepository();
            Console.Write("Confirm delete (y/N): ");
            var key = Console.ReadKey();
            Console.WriteLine();
            if (char.ToLowerInvariant(key.KeyChar) == 'y')
            {
                Console.WriteLine(repo.Remove(id) ? "Deleted." : "Not found.");
            }
            else Console.WriteLine("Cancelled.");
        }

        /// <summary>
        /// Changes the master password by re-encrypting all records with a new key and salt.
        /// </summary>
        private void CmdChangeMaster()
        {
            RequireUnlocked();
            var current = PromptHidden("Current master password: ");
            if (!_session.VerifyMaster(current)) { Console.WriteLine("Invalid current master password."); return; }
            var next = PromptHidden("New master password: ");
            var confirm = PromptHidden("Confirm new master password: ");
            if (next != confirm) { Console.WriteLine("Passwords do not match."); return; }

            var newSalt = RandomNumberGenerator.GetBytes(16);
            var iterations = _vault.Metadata.KdfIterations; // keep same; could prompt to change

            using var oldKey = _session.CurrentKey!; // currently active
            using var newKey = _kdf.DeriveKey(next, newSalt, iterations);

            foreach (var c in _vault.Credentials)
            {
                var aad = Encoding.UTF8.GetBytes($"{c.Service}\u0001{c.Username}");
                var plaintext = _enc.Decrypt(c.Nonce, c.Ciphertext, oldKey.AesKey, aad);
                try
                {
                    var (nonce, cipher) = _enc.Encrypt(plaintext, newKey.AesKey, aad);
                    c.Nonce = nonce;
                    c.Ciphertext = cipher;
                    c.UpdatedAtUtc = DateTimeOffset.UtcNow;
                }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
            }

            _vault.Metadata.KdfSalt = newSalt;
            using var hmac = new HMACSHA256(newKey.HmacKey);
            _vault.Metadata.VerificationHmac = hmac.ComputeHash(Encoding.UTF8.GetBytes("vault"));

            _store.Save(_vaultPath, _vault);
            _session.Lock();
            Console.WriteLine("Master password changed. Vault locked; use 'unlock' with the new password.");
        }

        /// <summary>
        /// Adjusts runtime settings and persists them to config.json.
        /// </summary>
        private void CmdSet(IReadOnlyList<string> args)
        {
            if (args.Count < 3)
            {
                Console.WriteLine("Usage: set <clipboard-timeout|idle-timeout|gen> <value|off|...>");
                Console.WriteLine("Examples: set clipboard-timeout 30 | set idle-timeout 10 | set gen length 24 | set gen symbols off");
                return;
            }
            var key = args[1].ToLowerInvariant();

            switch (key)
            {
                case "clipboard-timeout":
                    {
                        var val = args[2].ToLowerInvariant();
                        if (val == "off" || val == "0")
                        {
                            _clipboardClearAfter = TimeSpan.Zero;
                            _config.ClipboardTimeoutSeconds = 0;
                            _clipboardTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
                            Console.WriteLine("Clipboard auto-clear disabled.");
                        }
                        else if (int.TryParse(val, out var sec) && sec >= 0 && sec <= 600)
                        {
                            _clipboardClearAfter = TimeSpan.FromSeconds(sec);
                            _config.ClipboardTimeoutSeconds = sec;
                            Console.WriteLine($"Clipboard auto-clear set to {sec}s.");
                            ScheduleClipboardClear();
                        }
                        else { Console.WriteLine("Invalid seconds. Use 0..600 or 'off'."); return; }
                        break;
                    }

                case "idle-timeout":
                    {
                        var val = args[2].ToLowerInvariant();
                        if (val == "off" || val == "0")
                        {
                            _idleTimeout = TimeSpan.Zero;
                            _config.IdleTimeoutMinutes = 0;
                            StopIdleTimer();
                            Console.WriteLine("Auto-lock disabled.");
                        }
                        else if (int.TryParse(val, out var minutes) && minutes >= 0 && minutes <= 120)
                        {
                            _idleTimeout = TimeSpan.FromMinutes(minutes);
                            _config.IdleTimeoutMinutes = minutes;
                            Console.WriteLine($"Auto-lock set to {minutes}m.");
                            ResetIdleTimer();
                        }
                        else { Console.WriteLine("Invalid minutes. Use 0..120 or 'off'."); return; }
                        break;
                    }

                case "gen":
                    {
                        if (args.Count < 4)
                        {
                            Console.WriteLine("Usage: set gen <length|upper|lower|digits|symbols|ambiguous> <value>");
                            Console.WriteLine("Examples: set gen length 24 | set gen symbols off | set gen ambiguous allow");
                            return;
                        }
                        var sub = args[2].ToLowerInvariant();
                        var val = args[3].ToLowerInvariant();
                        switch (sub)
                        {
                            case "length":
                                if (int.TryParse(val, out var n) && n >= 8 && n <= 128)
                                { _config.GeneratorLength = n; Console.WriteLine($"Generator length set to {n}."); }
                                else { Console.WriteLine("Length must be 8..128."); return; }
                                break;
                            case "upper":
                                if (TryParseOnOff(val, out var u)) { _config.GeneratorUpper = u; Console.WriteLine($"Generator upper: {(u ? "on" : "off")}."); }
                                else { Console.WriteLine("Use on|off."); return; }
                                break;
                            case "lower":
                                if (TryParseOnOff(val, out var l)) { _config.GeneratorLower = l; Console.WriteLine($"Generator lower: {(l ? "on" : "off")}."); }
                                else { Console.WriteLine("Use on|off."); return; }
                                break;
                            case "digits":
                                if (TryParseOnOff(val, out var d)) { _config.GeneratorDigits = d; Console.WriteLine($"Generator digits: {(d ? "on" : "off")}."); }
                                else { Console.WriteLine("Use on|off."); return; }
                                break;
                            case "symbols":
                                if (TryParseOnOff(val, out var s)) { _config.GeneratorSymbols = s; Console.WriteLine($"Generator symbols: {(s ? "on" : "off")}."); }
                                else { Console.WriteLine("Use on|off."); return; }
                                break;
                            case "ambiguous":
                                if (val is "allow" or "on" or "true" or "1") { _config.GeneratorExcludeAmbiguous = false; Console.WriteLine("Generator ambiguous: allow."); }
                                else if (val is "deny" or "off" or "false" or "0") { _config.GeneratorExcludeAmbiguous = true; Console.WriteLine("Generator ambiguous: deny."); }
                                else { Console.WriteLine("Use allow|deny or on|off."); return; }
                                break;
                            default:
                                Console.WriteLine("Unknown gen setting. Use length|upper|lower|digits|symbols|ambiguous");
                                return;
                        }
                        break;
                    }

                default:
                    Console.WriteLine("Unknown setting. Supported: clipboard-timeout, idle-timeout, gen");
                    return;
            }

            try { _configStore.Save(_configPath, _config); }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"Warning: failed to save config: {ex.Message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Parses common on/off tokens into a boolean (on/true/1 vs off/false/0).
        /// </summary>
        private static bool TryParseOnOff(string val, out bool result)
        {
            switch (val)
            {
                case "on": case "true": case "1": result = true; return true;
                case "off": case "false": case "0": result = false; return true;
                default: result = false; return false;
            }
        }

        /// <summary>
        /// Reloads the vault from disk and returns a repository bound to the current master key.
        /// </summary>
        private JsonCredentialRepository CreateRepository()
        {
            if (!_session.IsUnlocked || _session.CurrentKey == null)
                throw new InvalidOperationException("Unlock the vault first.");
            // refresh vault from disk in case of external changes
            _vault = _store.LoadOrCreate(_vaultPath);
            return new JsonCredentialRepository(_vaultPath, _vault, _store, _enc, _session.CurrentKey);
        }

        /// <summary>
        /// Prints the banner header with current runtime settings (pretty, colored).
        /// </summary>
        private void WriteHeader()
        {
            int width = GetSafeWindowWidth();
            int ruleWidth = Math.Clamp(width - 2, 60, 100); // keep it nice even on very wide consoles
            string rule = new string('═', ruleWidth);

            Console.Clear();
            // top rule
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(rule);
            Console.ResetColor();

            // centered title
            var title = "Kvault Password Manager";
            int pad = Math.Max(0, (ruleWidth - title.Length) / 2);
            Console.Write(new string(' ', pad));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(title);
            Console.ResetColor();

            // sub rule
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(rule);
            Console.ResetColor();

            // “badges” line
            WriteBadge("AES‑GCM", ConsoleColor.Cyan);
            Console.Write("  ");
            WriteBadge("PBKDF2", ConsoleColor.Cyan);
            Console.Write("  ");
            WriteBadge("JSON Store", ConsoleColor.Cyan);
            Console.WriteLine();

            // settings line(s)
            var autoStr = _idleTimeout > TimeSpan.Zero ? $"Auto‑lock {_idleTimeout.TotalMinutes:0}m" : "Auto‑lock off";
            var clipStr = _clipboardClearAfter > TimeSpan.Zero ? $"Clipboard clear {_clipboardClearAfter.TotalSeconds:0}s" : "Clipboard clear off";

            WriteKvp("Auto‑lock", autoStr, _idleTimeout > TimeSpan.Zero ? ConsoleColor.Yellow : ConsoleColor.DarkYellow);
            WriteKvp("Clipboard", clipStr, _clipboardClearAfter > TimeSpan.Zero ? ConsoleColor.Yellow : ConsoleColor.DarkYellow);
            Console.WriteLine();

            // bottom rule
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(rule);
            Console.ResetColor();
        }

        // === small helpers ===
        private static void WriteBadge(string text, ConsoleColor bg)
        {
            Console.ForegroundColor = ConsoleColor.Black;
            Console.BackgroundColor = bg;
            Console.Write($" {text} ");
            Console.ResetColor();
        }

        private static void WriteKvp(string key, string value, ConsoleColor valueColor)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Write("  " + key + ": ");
            Console.ResetColor();
            Console.ForegroundColor = valueColor;
            Console.Write(value);
            Console.ResetColor();
            Console.Write("  ");
        }

        /// <summary>
        /// Displays the command help.
        /// </summary>
        private static void PrintHelp()
        {
            Console.WriteLine(@"Commands:
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
  
  exit|quit|bye                        Exit app");
        }

        /// <summary>
        /// Displays the command help with colors and tidy formatting.
        /// </summary>
        private static void PrintHelpDetailed()
        {
            int width = GetSafeWindowWidth();
            int leftPad = 2;                 // left margin
            int cmdColWidth = 38;            // width reserved for the command column
            int descWidth = Math.Max(20, width - leftPad - cmdColWidth - 3);

            void Section(string title)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine(new string(' ', leftPad) + title);
                Console.ResetColor();
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine(new string(' ', leftPad) + new string('─', Math.Min(title.Length, Math.Max(20, width - leftPad - 2))));
                Console.ResetColor();
            }

            void Cmd(string cmd, string desc, ConsoleColor cmdColor = ConsoleColor.Yellow)
            {
                // first line
                Console.ForegroundColor = cmdColor;
                Console.Write(new string(' ', leftPad) + cmd.PadRight(cmdColWidth));
                Console.ResetColor();

                var lines = Wrap(desc, descWidth);
                Console.WriteLine(lines[0]);

                // continuation lines for wrapped description
                for (int i = 1; i < lines.Count; i++)
                {
                    Console.Write(new string(' ', leftPad) + new string(' ', cmdColWidth));
                    Console.WriteLine(lines[i]);
                }
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(new string(' ', leftPad) + "Password Manager — Commands");
            Console.ResetColor();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(new string(' ', leftPad) + "Tip: values in <angle brackets> are required; [square brackets] are optional.");
            Console.ResetColor();
            Console.WriteLine();

            Section("General");
            Cmd("help", "Show this help");
            Cmd("exit | quit | bye", "Exit app");
            Console.WriteLine();

            Section("Vault");
            Cmd("unlock", "Unlock the vault");
            Cmd("lock", "Lock the vault");
            Cmd("change-master", "Change master password (re‑encrypts all)");
            Console.WriteLine();

            Section("Listing & Search");
            Cmd("list [--tag <tag>]", "List passwords (optionally filter by tag)");
            Cmd("search <term>", "Search service / username / notes / tags");
            Console.WriteLine();

            Section("Credentials");
            Cmd("add <service> <user> [notes]", "Add a password (leave password empty to auto‑generate)");
            Cmd("get <service> <user> [--show]", "Copy password to clipboard (default). Add --show to print");
            Cmd("copy <service> <user>", "Explicitly copy password to clipboard");
            Cmd("update <id>", "Update password by credential id (leave empty to auto‑generate)");
            Cmd("remove <id>", "Remove credential by id");
            Console.WriteLine();

            Section("Tags");
            Cmd("tag <id> add <tag>", "Add one tag to a credential");
            Console.WriteLine();

            Section("Generator");
            Cmd("gen [len] [flags]", "Generate a password (copies by default). Flags: --show, --no-upper, --no-lower, --no-digits, --no-symbols, --allow-ambiguous");
            Console.WriteLine();

            Section("Settings");
            Cmd("set clipboard-timeout <seconds|off>", "Configure clipboard auto‑clear");
            Cmd("set idle-timeout <minutes|off>", "Configure auto‑lock timeout");
            Console.WriteLine();

            Console.ResetColor();

            // --- helpers ---
            static List<string> Wrap(string text, int maxWidth)
            {
                var words = text.Split(' ', StringSplitOptions.None);
                var lines = new List<string>();
                var sb = new StringBuilder();

                foreach (var w in words)
                {
                    if (w.Length > maxWidth)
                    {
                        if (sb.Length > 0) { lines.Add(sb.ToString()); sb.Clear(); }
                        int idx = 0;
                        while (idx < w.Length)
                        {
                            int take = Math.Min(maxWidth, w.Length - idx);
                            lines.Add(w.Substring(idx, take));
                            idx += take;
                        }
                        continue;
                    }

                    int addLen = (sb.Length == 0 ? 0 : 1) + w.Length;
                    if (sb.Length + addLen > maxWidth)
                    {
                        lines.Add(sb.ToString());
                        sb.Clear();
                    }
                    if (sb.Length > 0) sb.Append(' ');
                    sb.Append(w);
                }
                if (sb.Length > 0) lines.Add(sb.ToString());
                if (lines.Count == 0) lines.Add(string.Empty);
                return lines;
            }

            static int GetSafeWindowWidth()
            {
                try { return Math.Max(60, Console.WindowWidth); }
                catch { return 100; } // redirected output / CI
            }
        }


        /// <summary>
        /// Reads a line from the console while echoing asterisks instead of the typed characters.
        /// </summary>
        private static string PromptHidden(string prompt)
        {
            Console.Write(prompt);
            var sb = new StringBuilder();
            ConsoleKeyInfo key;
            while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
            {
                if (key.Key == ConsoleKey.Backspace && sb.Length > 0)
                {
                    sb.Length--; Console.Write("\b \b"); continue;
                }
                if (!char.IsControl(key.KeyChar)) { sb.Append(key.KeyChar); Console.Write('*'); }
            }
            Console.WriteLine();
            return sb.ToString();
        }

        /// <summary>
        /// Splits a command line into arguments with support for quoted segments.
        /// </summary>
        private static string[] SplitArgs(string input)
        {
            // naive splitter that supports quoted segments
            var args = new List<string>();
            var current = new StringBuilder();
            bool inQuotes = false;
            foreach (var ch in input)
            {
                if (ch == '"') { inQuotes = !inQuotes; continue; }
                if (char.IsWhiteSpace(ch) && !inQuotes)
                {
                    if (current.Length > 0) { args.Add(current.ToString()); current.Clear(); }
                }
                else current.Append(ch);
            }
            if (current.Length > 0) args.Add(current.ToString());
            return args.ToArray();
        }

        /// <summary>
        /// Timer callback that auto-locks the vault after the configured idle timeout.
        /// </summary>
        private void OnIdleTimeout(object? state)
        {
            lock (_idleSync)
            {
                if (!_session.IsUnlocked) return;
                _session.Lock();
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"[Auto-lock] Vault locked after {_idleTimeout.TotalMinutes:0} minutes of inactivity.");
                Console.ResetColor();
                Console.Write("pm> ");
            }
        }

        /// <summary>
        /// Resets the idle auto-lock timer when user activity occurs.
        /// </summary>
        private void ResetIdleTimer()
        {
            if (_session.IsUnlocked && _idleTimeout > TimeSpan.Zero)
                _idleTimer.Change(_idleTimeout, Timeout.InfiniteTimeSpan);
            else
                _idleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        /// <summary>
        /// Stops the idle auto-lock timer.
        /// </summary>
        private void StopIdleTimer()
        {
            _idleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        /// <summary>
        /// Timer callback that clears the OS clipboard, if enabled.
        /// </summary>
        private void OnClipboardClear(object? state)
        {
            try
            {
                _clipboard.SetText(string.Empty);
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[Clipboard] Cleared.");
                Console.ResetColor();
                Console.Write("pm> ");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"[Clipboard] Failed to clear: {ex.Message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// (Re)schedules the clipboard clearing timer according to the configured timeout.
        /// </summary>
        private void ScheduleClipboardClear()
        {
            if (_clipboardClearAfter <= TimeSpan.Zero)
            {
                _clipboardTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
                return;
            }
            _clipboardTimer.Change(_clipboardClearAfter, Timeout.InfiniteTimeSpan);
        }

        /// <summary>
        /// Throws if the vault is currently locked.
        /// </summary>
        private void RequireUnlocked()
        {
            if (!_session.IsUnlocked || _session.CurrentKey == null)
                throw new InvalidOperationException("Unlock the vault first using the 'unlock' command.");
        }
    }
}