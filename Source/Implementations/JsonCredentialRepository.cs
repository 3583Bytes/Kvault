using System.Security.Cryptography;
using System.Text;
using kvault.Source.DomainModels;
using kvault.Source.Abstractions;
using kvault.Source.Models;

namespace kvault.Source.Implementations
{
    public sealed class JsonCredentialRepository : ICredentialRepository, IDisposable
    {
        private readonly VaultData _vault;
        private readonly IVaultStore _store;
        private readonly IEncryptionService _enc;
        private readonly MasterKey _masterKey;
        private readonly string _path;
        private bool _disposed;

        /// <summary>
        /// Repository over an in-memory <see cref="VaultData"/> that persists to <see cref="IVaultStore"/>.
        /// </summary>
        public JsonCredentialRepository(string path, VaultData vault, IVaultStore store, IEncryptionService enc, MasterKey masterKey)
        {
            _path = path;
            _vault = vault;
            _store = store;
            _enc = enc;
            _masterKey = masterKey;
        }
        /// <summary>
        /// Returns credentials ordered by service then username (metadata only; passwords remain encrypted).
        /// </summary>
        public IEnumerable<Credential> List() => _vault.Credentials.OrderBy(c => c.Service).ThenBy(c => c.Username);

        /// <summary>
        /// Adds a new credential, encrypting the password with AES-GCM (AAD binds service+username), then saves.
        /// </summary>
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

        /// <summary>
        /// Adds a tag to an existing vault entry then saves
        /// </summary>
        public bool AddTags(Guid id, IEnumerable<string> tags)
        {
            var cred = _vault.Credentials.FirstOrDefault(c => c.Id == id);
            if (cred == null) return false;

            cred.Tags ??= new List<string>();
            foreach (var t in tags)
            {
                var tag = t?.Trim();
                if (string.IsNullOrWhiteSpace(tag)) continue;

                // prevent dupes (case-insensitive)
                if (!cred.Tags.Any(x => string.Equals(x, tag, StringComparison.OrdinalIgnoreCase)))
                    cred.Tags.Add(tag);
            }

            cred.UpdatedAtUtc = DateTimeOffset.UtcNow;
            _store.Save(_path, _vault);
            return true;
        }

        /// <summary>
        /// Removes tags; returns false if id not found.
        /// </summary>
        public bool RemoveTags(Guid id, IEnumerable<string> tags)
        {
            var cred = _vault.Credentials.FirstOrDefault(c => c.Id == id);
            if (cred == null) return false;
            var norm = new HashSet<string>(NormalizeTags(tags), StringComparer.OrdinalIgnoreCase);
            cred.Tags.RemoveAll(t => norm.Contains(t));
            cred.UpdatedAtUtc = DateTimeOffset.UtcNow;
            _store.Save(_path, _vault);
            return true;
        }

        /// <summary>
        /// Replaces the tag set with the provided tags; returns false if id not found.
        /// </summary>
        public bool SetTags(Guid id, IEnumerable<string> tags)
        {
            var cred = _vault.Credentials.FirstOrDefault(c => c.Id == id);
            if (cred == null) return false;
            var norm = NormalizeTags(tags);
            cred.Tags = norm;
            cred.UpdatedAtUtc = DateTimeOffset.UtcNow;
            _store.Save(_path, _vault);
            return true;
        }

        /// <summary>
        /// Normalizes tags: trim, lower-case, drop empties, limit length, and de-duplicate.
        /// </summary>
        private static List<string> NormalizeTags(IEnumerable<string>? tags)
        {
            var list = new List<string>();
            if (tags == null) return list;
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in tags)
            {
                if (string.IsNullOrWhiteSpace(raw)) continue;
                var t = raw.Trim();
                if (t.Length > 32) t = t.Substring(0, 32);
                t = t.ToLowerInvariant();
                if (set.Add(t)) list.Add(t);
            }
            return list;
        }

        /// <summary>
        /// Finds a credential by service/username (case-insensitive match on both fields).
        /// </summary>
        public Credential? FindByService(string service, string username)
        {
            return _vault.Credentials.FirstOrDefault(c =>
                string.Equals(c.Service, service, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(c.Username, username, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Removes a credential by id and persists the change.
        /// </summary>
        public bool Remove(Guid id)
        {
            var idx = _vault.Credentials.FindIndex(c => c.Id == id);
            if (idx < 0) return false;
            _vault.Credentials.RemoveAt(idx);
            _store.Save(_path, _vault);
            return true;
        }

        /// <summary>
        /// Re-encrypts and updates the password for an existing credential; returns false if id not found.
        /// </summary>
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

        /// <summary>
        /// Builds Additional Authenticated Data binding the record to its service and username.
        /// </summary>
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
}