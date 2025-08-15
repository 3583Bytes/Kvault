namespace KVault
{
    public interface IVaultSession
    {
        bool IsUnlocked { get; }
        MasterKey? CurrentKey { get; }
        void InitializeVault(string masterPassword);
        void Unlock(string masterPassword);
        void Lock();
        bool VerifyMaster(string masterPassword);
    }
}