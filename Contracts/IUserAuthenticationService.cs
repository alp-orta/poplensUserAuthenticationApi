using poplensUserAuthenticationApi.Models.Dtos;

namespace poplensUserAuthenticationApi.Contracts {
    public interface IUserAuthenticationService {
        Task<string> RegisterAsync(RegisterInfo registerDto);
        Task<string> LoginAsync(LoginInfo loginDto);
    }
}
