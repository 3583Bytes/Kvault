// Password Manager Console App
// High-quality, SOLID-oriented single-file implementation
// .NET 6+ compatible. Build with:  dotnet new console -n PasswordManager && replace Program.cs, then `dotnet run`


namespace KVault
{
    #region Program Entry
    public static class Program
    {
        /// <summary>
        /// Entry point: ensures data directory exists, resolves paths, and starts the app.
        /// </summary>
        public static void Main(string[] args)
        {
            var exeDir = AppContext.BaseDirectory;
            var dataDir = Path.Combine(exeDir, "data");
            Directory.CreateDirectory(dataDir);
            var vaultPath = args.Length > 0 ? args[0] : Path.Combine(dataDir, "vault.json");

            var configPath = Path.Combine(dataDir, "config.json");
            var app = new App(vaultPath, configPath);
            app.Run();
        }
    }
    #endregion
}
