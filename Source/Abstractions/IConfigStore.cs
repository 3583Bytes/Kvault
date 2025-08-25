using kvault.Source.Configuration;

namespace kvault.Source.Abstractions
{
    public interface IConfigStore
    {
        AppConfig LoadOrCreate(string path);
        void Save(string path, AppConfig config);
    }
}