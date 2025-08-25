using System.Text.Json;
using System.Text.Json.Serialization;
using kvault.Source.Abstractions;

namespace kvault.Source.Configuration
{
    public sealed class FileConfigStore : IConfigStore
    {
        private readonly JsonSerializerOptions _jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        public AppConfig LoadOrCreate(string path)
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            if (!File.Exists(path))
            {
                var cfg = new AppConfig();
                Save(path, cfg);
                return cfg;
            }
            using var fs = File.OpenRead(path);
            return JsonSerializer.Deserialize<AppConfig>(fs, _jsonOptions) ?? new AppConfig();
        }

        public void Save(string path, AppConfig config)
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = path + ".tmp";
            using (var fs = File.Create(tmp))
            {
                JsonSerializer.Serialize(fs, config, _jsonOptions);
            }
            if (File.Exists(path)) File.Replace(tmp, path, path + ".bak", ignoreMetadataErrors: true);
            else File.Move(tmp, path);
        }
    }

}