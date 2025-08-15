namespace KVault
{
    public sealed class VaultMetadata
    {
        public byte[] KdfSalt { get; set; } = Array.Empty<byte>();
        public int KdfIterations { get; set; } = 200_000; // reasonable default; tune for your environment
        public byte[] VerificationHmac { get; set; } = Array.Empty<byte>(); // HMAC(masterHmacKey, "vault")
        public string? FileVersion { get; set; } = "1";
    }
}