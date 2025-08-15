namespace KVault
{
    public interface IVaultStore
    {
        VaultData LoadOrCreate(string path);
        void Save(string path, VaultData data);
    }
}