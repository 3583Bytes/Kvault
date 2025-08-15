using System.Security.Cryptography;
using System.Text;

namespace KVault
{
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
}