namespace kvault.Source.Abstractions
{
    public enum PasswordStrength
    {
        VeryWeak,
        Weak,
        Moderate,
        Strong,
        VeryStrong
    }

    public interface IPasswordStrengthService
    {
        PasswordStrength GetStrength(string password);
    }
}