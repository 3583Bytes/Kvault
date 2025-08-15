namespace KVault
{
    public interface IKeyDerivationService
    {
        MasterKey DeriveKey(string masterPassword, byte[] salt, int iterations);
    }
}