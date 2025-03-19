using poplensUserAuthenticationApi.Models;
using poplensUserAuthenticationApi.Models.Dtos;

namespace poplensUserAuthenticationApi.Contracts {
    public interface IUserAuthenticationService {
        Task<string> RegisterAsync(RegisterInfo registerDto);
        Task<string> LoginAsync(LoginInfo loginDto);
        Task<Ids> FetchIdsFromUsername(string username);
        Task<Dictionary<Guid, string>> GetUsernamesByIdsAsync(List<Guid> userIds);
    }
}
