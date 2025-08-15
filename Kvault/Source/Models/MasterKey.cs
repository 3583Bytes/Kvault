using System.Security.Cryptography;

namespace KVault
{
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
}