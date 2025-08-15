using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KVault
{
    public sealed class FileVaultStore : IVaultStore
    {
        private readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public VaultData LoadOrCreate(string path)
        {
            if (!File.Exists(path))
            {
                var salt = RandomNumberGenerator.GetBytes(16);
                var meta = new VaultMetadata
                {
                    KdfSalt = salt,
                    KdfIterations = 200_000,
                    VerificationHmac = Array.Empty<byte>(),
                    FileVersion = "1"
                };
                var data = new VaultData { Metadata = meta, Credentials = new List<Credential>() };
                Save(path, data);
                return data;
            }

            using var fs = File.OpenRead(path);
            var dataLoaded = JsonSerializer.Deserialize<VaultData>(fs, _jsonOptions) ?? new VaultData();
            return dataLoaded;
        }

        public void Save(string path, VaultData data)
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            var tmp = path + ".tmp";
            using (var fs = File.Create(tmp))
            {
                JsonSerializer.Serialize(fs, data, _jsonOptions);
            }
            // atomic replace
            if (File.Exists(path)) File.Replace(tmp, path, path + ".bak", ignoreMetadataErrors: true);
            else File.Move(tmp, path);
        }
    }
}