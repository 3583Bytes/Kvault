namespace KVault
{
    public interface IConfigStore
    {
        AppConfig LoadOrCreate(string path);
        void Save(string path, AppConfig config);
    }
}