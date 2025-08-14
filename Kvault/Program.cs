// Password Manager Console App
// High-quality, SOLID-oriented single-file implementation
// .NET 6+ compatible. Build with:  dotnet new console -n PasswordManager && replace Program.cs, then `dotnet run`

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace PasswordManager
{
    #region Domain Models
    public sealed class Credential
    {
        public Guid Id { get; init; } = Guid.NewGuid();
        public string Service { get; set; } = string.Empty;            // e.g., "github.com"
        public string Username { get; set; } = string.Empty;           // e.g., "alice"
        public string? Notes { get; set; }                             // optional, stored plaintext by design choice
        public List<string> Tags { get; set; } = new List<string>();  // simple case-insensitive tags
        public byte[] Nonce { get; set; } = Array.Empty<byte>();       // per-record AES-GCM nonce
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();  // encrypted password (includes tag in last 16 bytes)
        public DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
        public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    }

    public sealed class VaultMetadata
    {
        public byte[] KdfSalt { get; set; } = Array.Empty<byte>();
        public int KdfIterations { get; set; } = 200_000; // reasonable default; tune for your environment
        public byte[] VerificationHmac { get; set; } = Array.Empty<byte>(); // HMAC(masterHmacKey, "vault")
        public string? FileVersion { get; set; } = "1";
    }

    public sealed class VaultData
    {
        public VaultMetadata Metadata { get; set; } = new VaultMetadata();
        public List<Credential> Credentials { get; set; } = new List<Credential>();
    }
    #endregion

    #region Abstractions
    public interface IVaultStore
    {
        VaultData LoadOrCreate(string path);
        void Save(string path, VaultData data);
    }

    public interface IKeyDerivationService
    {
        MasterKey DeriveKey(string masterPassword, byte[] salt, int iterations);
    }

    public interface IEncryptionService
    {
        (byte[] nonce, byte[] cipherWithTag) Encrypt(byte[] plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad);
        byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> cipherWithTag, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad);
    }

    public interface ICredentialRepository
    {
        IEnumerable<Credential> List();
        Credential Add(string service, string username, string? notes, ReadOnlySpan<char> password);
        Credential? FindByService(string service, string username);
        bool Remove(Guid id);
        bool UpdatePassword(Guid id, ReadOnlySpan<char> newPassword);
    }

    public interface IVaultSession
    {
        bool IsUnlocked { get; }
        MasterKey? CurrentKey { get; }
        void InitializeVault(string masterPassword);
        void Unlock(string masterPassword);
        void Lock();
        bool VerifyMaster(string masterPassword);
    }

    public interface IClipboardService
    {
        void SetText(string text);
    }

    public interface IPasswordGenerator
    {
        string Generate(int length = 20,
                         bool includeUpper = true,
                         bool includeLower = true,
                         bool includeDigits = true,
                         bool includeSymbols = true,
                         bool excludeAmbiguous = true);
    }
    #endregion

    #region Security Key Model
    public sealed class MasterKey : IDisposable
    {
        public byte[] AesKey { get; } // 32 bytes
        public byte[] HmacKey { get; } // 32 bytes
        public MasterKey(byte[] aesKey, byte[] hmacKey)
        {
            AesKey = aesKey;
            HmacKey = hmacKey;
        }
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(AesKey);
            CryptographicOperations.ZeroMemory(HmacKey);
        }
    }
    #endregion

    #region Implementations
    public sealed class FileVaultStore : IVaultStore
    {
        private readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public VaultData LoadOrCreate(string path)
        {
            if (!File.Exists(path))
            {
                var salt = RandomNumberGenerator.GetBytes(16);
                var meta = new VaultMetadata
                {
                    KdfSalt = salt,
                    KdfIterations = 200_000,
                    VerificationHmac = Array.Empty<byte>(),
                    FileVersion = "1"
                };
                var data = new VaultData { Metadata = meta, Credentials = new List<Credential>() };
                Save(path, data);
                return data;
            }

            using var fs = File.OpenRead(path);
            var dataLoaded = JsonSerializer.Deserialize<VaultData>(fs, _jsonOptions) ?? new VaultData();
            return dataLoaded;
        }

        public void Save(string path, VaultData data)
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            var tmp = path + ".tmp";
            using (var fs = File.Create(tmp))
            {
                JsonSerializer.Serialize(fs, data, _jsonOptions);
            }
            // atomic replace
            if (File.Exists(path)) File.Replace(tmp, path, path + ".bak", ignoreMetadataErrors: true);
            else File.Move(tmp, path);
        }
    }

    public sealed class Pbkdf2KeyDerivationService : IKeyDerivationService
    {
        public MasterKey DeriveKey(string masterPassword, byte[] salt, int iterations)
        {
            using var kdf = new Rfc2898DeriveBytes(masterPassword, salt, iterations, HashAlgorithmName.SHA256);
            var keyMaterial = kdf.GetBytes(64); // 32 for AES + 32 for HMAC
            var aesKey = new byte[32];
            var hmacKey = new byte[32];
            Buffer.BlockCopy(keyMaterial, 0, aesKey, 0, 32);
            Buffer.BlockCopy(keyMaterial, 32, hmacKey, 0, 32);
            CryptographicOperations.ZeroMemory(keyMaterial);
            return new MasterKey(aesKey, hmacKey);
        }
    }

    public sealed class AesGcmEncryptionService : IEncryptionService
    {
        public (byte[] nonce, byte[] cipherWithTag) Encrypt(byte[] plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            using var aes = new AesGcm(key);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

            var output = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, output, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, output, ciphertext.Length, tag.Length);
            CryptographicOperations.ZeroMemory(tag);
            return (nonce, output);
        }

        public byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> cipherWithTag, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad)
        {
            if (cipherWithTag.Length < 16) throw new CryptographicException("Ciphertext too short");
            var cipherLen = cipherWithTag.Length - 16;
            Span<byte> ciphertext = stackalloc byte[cipherLen];
            Span<byte> tag = stackalloc byte[16];
            cipherWithTag[..cipherLen].CopyTo(ciphertext);
            cipherWithTag[cipherLen..].CopyTo(tag);
            byte[] plaintext = new byte[cipherLen];
            using var aes = new AesGcm(key);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            return plaintext;
        }
    }

    public sealed class JsonCredentialRepository : ICredentialRepository, IDisposable
    {
        private readonly VaultData _vault;
        private readonly IVaultStore _store;
        private readonly IEncryptionService _enc;
        private readonly MasterKey _masterKey;
        private readonly string _path;
        private bool _disposed;

        public JsonCredentialRepository(string path, VaultData vault, IVaultStore store, IEncryptionService enc, MasterKey masterKey)
        {
            _path = path;
            _vault = vault;
            _store = store;
            _enc = enc;
            _masterKey = masterKey;
        }

        public IEnumerable<Credential> List() => _vault.Credentials.OrderBy(c => c.Service).ThenBy(c => c.Username);

        public Credential Add(string service, string username, string? notes, ReadOnlySpan<char> password)
        {
            var pwdBytes = Encoding.UTF8.GetBytes(password.ToString());
            try
            {
                var aad = BuildAad(service, username);
                var (nonce, cipher) = _enc.Encrypt(pwdBytes, _masterKey.AesKey, aad);
                var cred = new Credential
                {
                    Service = service,
                    Username = username,
                    Notes = notes,
                    Nonce = nonce,
                    Ciphertext = cipher,
                    UpdatedAtUtc = DateTimeOffset.UtcNow
                };
                _vault.Credentials.Add(cred);
                _store.Save(_path, _vault);
                return cred;
            }
            finally { CryptographicOperations.ZeroMemory(pwdBytes); }
        }

        public Credential? FindByService(string service, string username)
        {
            return _vault.Credentials.FirstOrDefault(c =>
                string.Equals(c.Service, service, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(c.Username, username, StringComparison.OrdinalIgnoreCase));
        }

        public bool Remove(Guid id)
        {
            var idx = _vault.Credentials.FindIndex(c => c.Id == id);
            if (idx < 0) return false;
            _vault.Credentials.RemoveAt(idx);
            _store.Save(_path, _vault);
            return true;
        }

        public bool UpdatePassword(Guid id, ReadOnlySpan<char> newPassword)
        {
            var cred = _vault.Credentials.FirstOrDefault(c => c.Id == id);
            if (cred == null) return false;
            var pwdBytes = Encoding.UTF8.GetBytes(newPassword.ToString());
            try
            {
                var aad = BuildAad(cred.Service, cred.Username);
                var (nonce, cipher) = _enc.Encrypt(pwdBytes, _masterKey.AesKey, aad);
                cred.Nonce = nonce;
                cred.Ciphertext = cipher;
                cred.UpdatedAtUtc = DateTimeOffset.UtcNow;
                _store.Save(_path, _vault);
                return true;
            }
            finally { CryptographicOperations.ZeroMemory(pwdBytes); }
        }

        private static byte[] BuildAad(string service, string username)
        {
            var raw = $"{service}\u0001{username}";
            return Encoding.UTF8.GetBytes(raw);
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                // No unmanaged resources to clean now, but placeholder for extensibility
                _disposed = true;
            }
        }
    }
    #endregion

    // Configuration
    public sealed class AppConfig
    {
        public int ClipboardTimeoutSeconds { get; set; } = 20; // 0 to disable
        public int IdleTimeoutMinutes { get; set; } = 5;       // 0 to disable
    }

    public interface IConfigStore
    {
        AppConfig LoadOrCreate(string path);
        void Save(string path, AppConfig config);
    }

    public sealed class FileConfigStore : IConfigStore
    {
        private readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public AppConfig LoadOrCreate(string path)
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            if (!File.Exists(path))
            {
                var cfg = new AppConfig();
                Save(path, cfg);
                return cfg;
            }
            using var fs = File.OpenRead(path);
            return JsonSerializer.Deserialize<AppConfig>(fs, _jsonOptions) ?? new AppConfig();
        }

        public void Save(string path, AppConfig config)
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = path + ".tmp";
            using (var fs = File.Create(tmp))
            {
                JsonSerializer.Serialize(fs, config, _jsonOptions);
            }
            if (File.Exists(path)) File.Replace(tmp, path, path + ".bak", ignoreMetadataErrors: true);
            else File.Move(tmp, path);
        }
    }

    public sealed class VaultSession : IVaultSession
    {
        private readonly VaultData _vault;
        private readonly IVaultStore _store;
        private readonly IKeyDerivationService _kdf;
        private readonly string _path;
        public MasterKey? CurrentKey { get; private set; }
        public bool IsUnlocked => CurrentKey != null;

        public VaultSession(string path, VaultData vault, IVaultStore store, IKeyDerivationService kdf)
        {
            _path = path; _vault = vault; _store = store; _kdf = kdf;
        }

        public void InitializeVault(string masterPassword)
        {
            if (_vault.Metadata.VerificationHmac is { Length: > 0 })
                throw new InvalidOperationException("Vault already initialized.");

            using var mk = _kdf.DeriveKey(masterPassword, _vault.Metadata.KdfSalt, _vault.Metadata.KdfIterations);
            var hmac = ComputeVerificationHmac(mk);
            _vault.Metadata.VerificationHmac = hmac;
            _store.Save(_path, _vault);
        }

        public bool VerifyMaster(string masterPassword)
        {
            using var mk = _kdf.DeriveKey(masterPassword, _vault.Metadata.KdfSalt, _vault.Metadata.KdfIterations);
            var h = ComputeVerificationHmac(mk);
            return CryptographicOperations.FixedTimeEquals(h, _vault.Metadata.VerificationHmac);
        }

        public void Unlock(string masterPassword)
        {
            if (!VerifyMaster(masterPassword)) throw new CryptographicException("Invalid master password.");
            CurrentKey = _kdf.DeriveKey(masterPassword, _vault.Metadata.KdfSalt, _vault.Metadata.KdfIterations);
        }

        public void Lock()
        {
            CurrentKey?.Dispose();
            CurrentKey = null;
        }

        private static byte[] ComputeVerificationHmac(MasterKey mk)
        {
            using var h = new HMACSHA256(mk.HmacKey);
            return h.ComputeHash(Encoding.UTF8.GetBytes("vault"));
        }
    }

    public sealed class CrossPlatformClipboardService : IClipboardService
    {
        public void SetText(string text)
        {
            if (string.IsNullOrEmpty(text)) return;

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                RunPipe("cmd.exe", "/c clip", text);
                return;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                RunPipe("pbcopy", null, text);
                return;
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // Try xclip, then xsel
                try { RunPipe("xclip", "-selection clipboard", text); }
                catch { RunPipe("xsel", "-b", text); }
                return;
            }

            throw new PlatformNotSupportedException("Clipboard unsupported on this platform.");
        }

        private static void RunPipe(string fileName, string? arguments, string input)
        {
            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments ?? string.Empty,
                RedirectStandardInput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi) ?? throw new InvalidOperationException($"Failed to start {fileName}");
            using var sw = p.StandardInput;
            sw.Write(input);
            sw.Flush();
            sw.Close();
            p.WaitForExit();
            if (p.ExitCode != 0)
                throw new InvalidOperationException($"Clipboard command '{fileName} {arguments}' exited with {p.ExitCode}.");
        }
    }

    public sealed class CryptoPasswordGenerator : IPasswordGenerator
    {
        // Ambiguous characters (visually similar) excluded by default
        private const string Upper = "ABCDEFGHJKMNPQRSTUVWXYZ"; // no I, L, O
        private const string Lower = "abcdefghjkmnpqrstuvwxyz"; // no i, l, o
        private const string Digits = "23456789";               // no 0,1
        private const string Symbols = "!@#$%^&*()-_=+[]{};:,.?/";
        private const string Ambiguous = "Il1O0|`'\"~<>\\/";

        public string Generate(int length = 20, bool includeUpper = true, bool includeLower = true, bool includeDigits = true, bool includeSymbols = true, bool excludeAmbiguous = true)
        {
            if (length < 8) length = 8;
            if (!includeUpper && !includeLower && !includeDigits && !includeSymbols)
                throw new ArgumentException("At least one character class must be enabled.");

            var pools = new List<string>();
            if (includeUpper) pools.Add(Upper);
            if (includeLower) pools.Add(Lower);
            if (includeDigits) pools.Add(Digits);
            if (includeSymbols) pools.Add(Symbols);

            var all = string.Concat(pools);
            if (!excludeAmbiguous) all += Ambiguous;

            var chars = new char[length];
            int idx = 0;

            // Guarantee at least one from each enabled pool
            foreach (var pool in pools)
            {
                chars[idx++] = pool[NextInt32(pool.Length)];
            }
            // Fill the rest from combined pool
            for (; idx < length; idx++)
            {
                chars[idx] = all[NextInt32(all.Length)];
            }

            // Shuffle to remove predictability of first characters
            Shuffle(chars);
            return new string(chars);
        }

        private static void Shuffle(char[] array)
        {
            for (int i = array.Length - 1; i > 0; i--)
            {
                int j = NextInt32(i + 1);
                (array[i], array[j]) = (array[j], array[i]);
            }
        }

        private static int NextInt32(int maxExclusive)
        {
            if (maxExclusive <= 0) throw new ArgumentOutOfRangeException(nameof(maxExclusive));
            Span<byte> b = stackalloc byte[4];
            uint bound = (uint.MaxValue / (uint)maxExclusive) * (uint)maxExclusive; // rejection sampling to avoid modulo bias
            uint r;
            do
            {
                RandomNumberGenerator.Fill(b);
                r = BitConverter.ToUInt32(b);
            } while (r >= bound);
            return (int)(r % (uint)maxExclusive);
        }
    }

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
                        case "help": PrintHelp(); break;
                        case "unlock": CmdUnlock(); break;
                        case "lock": CmdLock(); break;
                        case "add": CmdAdd(parts); break;
                        case "get": CmdGet(parts); break;
                        case "copy": CmdCopy(parts); break;
                        case "gen": CmdGen(parts); break;
                        case "list": CmdList(parts); break;
                        case "search": CmdSearch(parts); break;
                        case "update": CmdUpdate(parts); break;
                        case "remove": CmdRemove(parts); break;
                        case "change-master": CmdChangeMaster(); break;
                        case "set": CmdSet(parts); break;
                        case "exit": case "quit": return;
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

        private void CmdUnlock()
        {
            if (_session.IsUnlocked) { Console.WriteLine("Already unlocked."); return; }
            var master = PromptHidden("Master password: ");
            _session.Unlock(master);
            ResetIdleTimer();
            Console.WriteLine("Unlocked.");
        }

        private void CmdLock()
        {
            StopIdleTimer();
            _session.Lock();
            Console.WriteLine("Locked.");
        }

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
                pwd = _passwordGenerator.Generate();
                _clipboard.SetText(pwd);
                Console.WriteLine("Generated a strong password and copied to clipboard.");
            }

            using var repo = CreateRepository();
            var cred = repo.Add(service, username, notes, pwd);
            Console.WriteLine($"Added: {cred.Id} ({cred.Service}/{cred.Username})");
        }

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
                    Console.WriteLine("Password copied to clipboard.");
                    ScheduleClipboardClear();
                }
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }

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
                Console.WriteLine("Password copied to clipboard.");
                ScheduleClipboardClear();
            }
            finally { CryptographicOperations.ZeroMemory(plaintext); }
        }

        private void CmdGen(IReadOnlyList<string> args)
        {
            int length = 20;
            bool show = args.Skip(1).Any(a => a.Equals("--show", StringComparison.OrdinalIgnoreCase) || a.Equals("-s", StringComparison.OrdinalIgnoreCase));
            bool includeUpper = true, includeLower = true, includeDigits = true, includeSymbols = true, excludeAmbiguous = true;

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
                Console.WriteLine($"Generated: {pwd}");
            }
            else
            {
                _clipboard.SetText(pwd);
                Console.WriteLine("Generated password copied to clipboard.");
                ScheduleClipboardClear();
            }
        }

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
            foreach (var c in results)
            {
                var tags = (c.Tags == null || c.Tags.Count == 0) ? "-" : string.Join(',', c.Tags);
                Console.WriteLine($"{c.Id}  |  {c.Service}  |  {c.Username}  |  tags: {tags}  |  updated {c.UpdatedAtUtc:yyyy-MM-dd HH:mm}Z");
            }
        }

        private void CmdList(IReadOnlyList<string> args)
        {
            RequireUnlocked();
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
            foreach (var c in list)
            {
                var tags = (c.Tags == null || c.Tags.Count == 0) ? "-" : string.Join(',', c.Tags);
                Console.WriteLine($"{c.Id}  |  {c.Service}  |  {c.Username}  |  tags: {tags}  |  updated {c.UpdatedAtUtc:yyyy-MM-dd HH:mm}Z");
            }
        }

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
                pwd = _passwordGenerator.Generate();
                _clipboard.SetText(pwd);
                Console.WriteLine("Generated and copied new password to clipboard.");
                ScheduleClipboardClear();
            }
            using var repo = CreateRepository();
            if (repo.UpdatePassword(id, pwd)) Console.WriteLine("Updated."); else Console.WriteLine("Not found.");
        }

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

        private void CmdSet(IReadOnlyList<string> args)
        {
            if (args.Count < 3)
            {
                Console.WriteLine("Usage: set <clipboard-timeout|idle-timeout> <value|off>");
                return;
            }
            var key = args[1].ToLowerInvariant();
            var val = args[2].ToLowerInvariant();

            switch (key)
            {
                case "clipboard-timeout":
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

                case "idle-timeout":
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

                default:
                    Console.WriteLine("Unknown setting. Supported: clipboard-timeout, idle-timeout");
                    return;
            }

            // Persist config
            try { _configStore.Save(_configPath, _config); }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"Warning: failed to save config: {ex.Message}");
                Console.ResetColor();
            }
        }

        private JsonCredentialRepository CreateRepository()
        {
            if (!_session.IsUnlocked || _session.CurrentKey == null)
                throw new InvalidOperationException("Unlock the vault first.");
            // refresh vault from disk in case of external changes
            _vault = _store.LoadOrCreate(_vaultPath);
            return new JsonCredentialRepository(_vaultPath, _vault, _store, _enc, _session.CurrentKey);
        }

        private void WriteHeader()
        {
            Console.WriteLine("==============================");
            Console.WriteLine("  Password Manager (Console)");
            var autoStr = _idleTimeout > TimeSpan.Zero ? $"Auto-lock {_idleTimeout.TotalMinutes:0}m" : "Auto-lock off";
            var clipStr = _clipboardClearAfter > TimeSpan.Zero ? $"Clipboard clear {_clipboardClearAfter.TotalSeconds:0}s" : "Clipboard clear off";
            Console.WriteLine($"  AES-GCM | PBKDF2 | JSON Store | {autoStr} | {clipStr}");
            Console.WriteLine("==============================");
        }

        private static void PrintHelp()
        {
            Console.WriteLine(@"Commands:
  help                     Show this help
  unlock                   Unlock the vault
  lock                     Lock the vault
  add <service> <user> [notes]   Add a credential (leave password empty to auto-generate)
  get <service> <user> [--show]  Copy password to clipboard (default). Add --show to print
  copy <service> <user>    Explicitly copy password to clipboard
  gen [len] [flags]        Generate a password (copies by default). Flags: --show, --no-upper, --no-lower, --no-digits, --no-symbols, --allow-ambiguous
  list [--tag <tag>]       List credentials (optionally filter by tag)
  search <term>            Search service/username/notes/tags
  update <id>              Update password by credential id (leave empty to auto-generate)
  remove <id>              Remove credential by id
  change-master            Change master password (re-encrypts all)
  set clipboard-timeout <seconds|off>  Configure clipboard auto-clear (persisted)
  set idle-timeout <minutes|off>       Configure auto-lock timeout (persisted)
  exit|quit                Exit app");
        }

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

        private void ResetIdleTimer()
        {
            if (_session.IsUnlocked && _idleTimeout > TimeSpan.Zero)
                _idleTimer.Change(_idleTimeout, Timeout.InfiniteTimeSpan);
            else
                _idleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        private void StopIdleTimer()
        {
            _idleTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

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

        private void ScheduleClipboardClear()
        {
            if (_clipboardClearAfter <= TimeSpan.Zero)
            {
                _clipboardTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
                return;
            }
            _clipboardTimer.Change(_clipboardClearAfter, Timeout.InfiniteTimeSpan);
        }

        private void RequireUnlocked()
        {
            if (!_session.IsUnlocked || _session.CurrentKey == null)
                throw new InvalidOperationException("Unlock the vault first using the 'unlock' command.");
        }
    }

    #region Program Entry
    public static class Program
    {
        public static void Main(string[] args)
        {
            var exeDir = AppContext.BaseDirectory;
            var dataDir = Path.Combine(exeDir, "data");
            Directory.CreateDirectory(dataDir);
            var vaultPath = args.Length > 0 ? args[0] : Path.Combine(dataDir, "vault.json");

            var configPath = Path.Combine(dataDir, "config.json");
            var app = new App(vaultPath, configPath);
            app.Run();
        }
    }
    #endregion
}
