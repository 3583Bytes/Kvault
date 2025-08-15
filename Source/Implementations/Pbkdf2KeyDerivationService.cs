using System.Security.Cryptography;

namespace KVault
{
    public sealed class Pbkdf2KeyDerivationService : IKeyDerivationService
    {
        /// <summary>
        /// Derives a 64-byte key using PBKDF2-SHA256 and splits it into 32B AES and 32B HMAC keys.
        /// </summary>
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
}