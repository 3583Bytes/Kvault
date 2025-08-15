using System.Security.Cryptography;

namespace KVault
{
    public sealed class AesGcmEncryptionService : IEncryptionService
    {
        public (byte[] nonce, byte[] cipherWithTag) Encrypt(byte[] plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[16];
            using var aes = new AesGcm(key, 16);
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
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            return plaintext;
        }
    }

}