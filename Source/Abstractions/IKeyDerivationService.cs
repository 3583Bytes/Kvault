using kvault.Source.Models;

namespace kvault.Source.Abstractions
{
    public interface IKeyDerivationService
    {
        MasterKey DeriveKey(string masterPassword, byte[] salt, int iterations);
    }
}