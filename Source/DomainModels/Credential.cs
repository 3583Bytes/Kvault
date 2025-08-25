namespace kvault.Source.DomainModels
{
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
}