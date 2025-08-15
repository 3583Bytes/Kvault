namespace KVault
{
    public interface IPasswordGenerator
    {
        string Generate(int length = 20,
                         bool includeUpper = true,
                         bool includeLower = true,
                         bool includeDigits = true,
                         bool includeSymbols = true,
                         bool excludeAmbiguous = true);
    }
}