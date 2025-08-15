namespace KVault
{
    public sealed class VaultData
    {
        public VaultMetadata Metadata { get; set; } = new VaultMetadata();
        public List<Credential> Credentials { get; set; } = new List<Credential>();
    }
}