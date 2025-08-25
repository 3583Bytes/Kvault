namespace kvault.Source.Abstractions
{
    public interface IEncryptionService
    {
        (byte[] nonce, byte[] cipherWithTag) Encrypt(byte[] plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad);
        byte[] Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> cipherWithTag, ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad);
    }
}