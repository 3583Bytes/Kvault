using kvault.Source.Abstractions;
using System.Linq;

namespace kvault.Source.Implementations
{
    public sealed class PasswordStrengthService : IPasswordStrengthService
    {
        public PasswordStrength GetStrength(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return PasswordStrength.VeryWeak;
            }

            int score = 0;

            // Length
            if (password.Length < 8) score += 0;
            else if (password.Length < 12) score += 1;
            else if (password.Length < 16) score += 2;
            else score += 3;

            // Character types
            bool hasUpper = password.Any(char.IsUpper);
            bool hasLower = password.Any(char.IsLower);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSymbol = password.Any(char.IsSymbol) || password.Any(char.IsPunctuation);

            if (hasUpper) score += 1;
            if (hasLower) score += 1;
            if (hasDigit) score += 1;
            if (hasSymbol) score += 1;

            // Map score to strength
            if (score < 2) return PasswordStrength.VeryWeak;
            if (score < 4) return PasswordStrength.Weak;
            if (score < 6) return PasswordStrength.Moderate;
            if (score < 8) return PasswordStrength.Strong;
            return PasswordStrength.VeryStrong;
        }
    }
}
