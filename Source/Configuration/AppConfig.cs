namespace KVault
{
    // Configuration
    /// <summary>
    /// Application configuration persisted to data/config.json.
    /// Controls timeouts and default password generator settings.
    /// </summary>
    public sealed class AppConfig
    {
        /// <summary>
        /// Clipboard auto-clear timeout in seconds; 0 disables auto-clear.
        /// </summary>
        public int ClipboardTimeoutSeconds { get; set; } = 20; // 0 to disable

        /// <summary>
        /// Idle time (minutes) before auto-lock; 0 disables auto-lock.
        /// </summary>
        public int IdleTimeoutMinutes { get; set; } = 5;       // 0 to disable
        
        // Password generator defaults
        /// <summary>
        /// Default generated password length (8..128).
        /// </summary>
        public int GeneratorLength { get; set; } = 20;         // 8..128
        /// <summary>
        /// Include uppercase letters by default.
        /// </summary>
        public bool GeneratorUpper { get; set; } = true;
        /// <summary>
        /// Include lowercase letters by default.
        /// </summary>
        public bool GeneratorLower { get; set; } = true;
        /// <summary>
        /// Include digits by default.
        /// </summary>
        public bool GeneratorDigits { get; set; } = true;
        /// <summary>
        /// Include symbols by default.
        /// </summary>
        public bool GeneratorSymbols { get; set; } = true;
        /// <summary>
        /// Exclude ambiguous look-alike characters by default.
        /// </summary>
        public bool GeneratorExcludeAmbiguous { get; set; } = true; // true = exclude visually similar
    }
}