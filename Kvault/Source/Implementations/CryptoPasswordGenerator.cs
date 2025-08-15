using System.Security.Cryptography;

namespace KVault
{
    public sealed class CryptoPasswordGenerator : IPasswordGenerator
    {
        // Ambiguous characters (visually similar) excluded by default
        private const string Upper = "ABCDEFGHJKMNPQRSTUVWXYZ"; // no I, L, O
        private const string Lower = "abcdefghjkmnpqrstuvwxyz"; // no i, l, o
        private const string Digits = "23456789";               // no 0,1
        private const string Symbols = "!@#$%^&*()-_=+[]{};:,.?/";
        private const string Ambiguous = "Il1O0|`'\"~<>\\/";

        public string Generate(int length = 20, bool includeUpper = true, bool includeLower = true, bool includeDigits = true, bool includeSymbols = true, bool excludeAmbiguous = true)
        {
            if (length < 8) length = 8;
            if (!includeUpper && !includeLower && !includeDigits && !includeSymbols)
                throw new ArgumentException("At least one character class must be enabled.");

            var pools = new List<string>();
            if (includeUpper) pools.Add(Upper);
            if (includeLower) pools.Add(Lower);
            if (includeDigits) pools.Add(Digits);
            if (includeSymbols) pools.Add(Symbols);

            var all = string.Concat(pools);
            if (!excludeAmbiguous) all += Ambiguous;

            var chars = new char[length];
            int idx = 0;

            // Guarantee at least one from each enabled pool
            foreach (var pool in pools)
            {
                chars[idx++] = pool[NextInt32(pool.Length)];
            }
            // Fill the rest from combined pool
            for (; idx < length; idx++)
            {
                chars[idx] = all[NextInt32(all.Length)];
            }

            // Shuffle to remove predictability of first characters
            Shuffle(chars);
            return new string(chars);
        }

        private static void Shuffle(char[] array)
        {
            for (int i = array.Length - 1; i > 0; i--)
            {
                int j = NextInt32(i + 1);
                (array[i], array[j]) = (array[j], array[i]);
            }
        }

        private static int NextInt32(int maxExclusive)
        {
            if (maxExclusive <= 0) throw new ArgumentOutOfRangeException(nameof(maxExclusive));
            Span<byte> b = stackalloc byte[4];
            uint bound = (uint.MaxValue / (uint)maxExclusive) * (uint)maxExclusive; // rejection sampling to avoid modulo bias
            uint r;
            do
            {
                RandomNumberGenerator.Fill(b);
                r = BitConverter.ToUInt32(b);
            } while (r >= bound);
            return (int)(r % (uint)maxExclusive);
        }
    }

}