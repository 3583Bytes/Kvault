using kvault.Source.DomainModels;

namespace kvault.Source.Abstractions
{
    public interface ICredentialRepository
    {
        IEnumerable<Credential> List();
        Credential Add(string service, string username, string? notes, ReadOnlySpan<char> password);
        Credential? FindByService(string service, string username);
        bool Remove(Guid id);
        bool UpdatePassword(Guid id, ReadOnlySpan<char> newPassword);
    }
}