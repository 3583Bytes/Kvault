namespace KVault
{
    public sealed class AppConfig
    {
        public int ClipboardTimeoutSeconds { get; set; } = 20; // 0 to disable
        public int IdleTimeoutMinutes { get; set; } = 5;       // 0 to disable

        // Password generator defaults
        public int GeneratorLength { get; set; } = 20;         // 8..128
        public bool GeneratorUpper { get; set; } = true;
        public bool GeneratorLower { get; set; } = true;
        public bool GeneratorDigits { get; set; } = true;
        public bool GeneratorSymbols { get; set; } = true;
        public bool GeneratorExcludeAmbiguous { get; set; } = true; // true = exclude visually similar
    }
}