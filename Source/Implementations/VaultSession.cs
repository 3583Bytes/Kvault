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

        /// <summary>
        /// Creates a session over a vault; holds the in-memory master key only while unlocked.
        /// </summary>
        public VaultSession(string path, VaultData vault, IVaultStore store, IKeyDerivationService kdf)
        {
            _path = path; _vault = vault; _store = store; _kdf = kdf;
        }

        /// <summary>
        /// Initializes a fresh vault by deriving the master keys and storing a verification HMAC.
        /// </summary>
        public void InitializeVault(string masterPassword)
        {
            if (_vault.Metadata.VerificationHmac is { Length: > 0 })
                throw new InvalidOperationException("Vault already initialized.");

            using var mk = _kdf.DeriveKey(masterPassword, _vault.Metadata.KdfSalt, _vault.Metadata.KdfIterations);
            var hmac = ComputeVerificationHmac(mk);
            _vault.Metadata.VerificationHmac = hmac;
            _store.Save(_path, _vault);
        }

        /// <summary>
        /// Verifies a master password without keeping the derived key (compares verification HMAC).
        /// </summary>
        public bool VerifyMaster(string masterPassword)
        {
            using var mk = _kdf.DeriveKey(masterPassword, _vault.Metadata.KdfSalt, _vault.Metadata.KdfIterations);
            var h = ComputeVerificationHmac(mk);
            return CryptographicOperations.FixedTimeEquals(h, _vault.Metadata.VerificationHmac);
        }

        /// <summary>
        /// Derives and retains the master key for the current process lifetime (until <see cref="Lock"/>).
        /// </summary>
        public void Unlock(string masterPassword)
        {
            if (!VerifyMaster(masterPassword)) throw new CryptographicException("Invalid master password.");
            CurrentKey = _kdf.DeriveKey(masterPassword, _vault.Metadata.KdfSalt, _vault.Metadata.KdfIterations);
        }

        /// <summary>
        /// Disposes and forgets the in-memory master key.
        /// </summary>
        public void Lock()
        {
            CurrentKey?.Dispose();
            CurrentKey = null;
        }

        /// <summary>
        /// Computes the vault verification HMAC using the HMAC subkey and a fixed label.
        /// </summary>
        private static byte[] ComputeVerificationHmac(MasterKey mk)
        {
            using var h = new HMACSHA256(mk.HmacKey);
            return h.ComputeHash(Encoding.UTF8.GetBytes("vault"));
        }
    }
}