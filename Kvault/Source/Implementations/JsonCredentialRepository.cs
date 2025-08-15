using System.Security.Cryptography;
using System.Text;

namespace KVault
{
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
}