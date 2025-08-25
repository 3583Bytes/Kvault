using kvault.Source.DomainModels;

namespace kvault.Source.Abstractions
{
    public interface IVaultStore
    {
        VaultData LoadOrCreate(string path);
        void Save(string path, VaultData data);
    }
}