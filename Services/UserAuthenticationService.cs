using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using poplensUserAuthenticationApi.Contracts;
using poplensUserAuthenticationApi.Models;
using poplensUserAuthenticationApi.Models.Dtos;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace poplensUserAuthenticationApi.Services {
    public class UserAuthenticationService : IUserAuthenticationService {
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _configuration;

        public UserAuthenticationService(UserManager<User> userManager, IConfiguration configuration) {
            _userManager = userManager;
            _configuration = configuration;
        }

        public async Task<string> RegisterAsync(RegisterInfo registerInfo) {
            Console.WriteLine($"DB_CONNECTION_STRING: {Environment.GetEnvironmentVariable("DB_CONNECTION_STRING")}"); // Debugging output
            Guard.Against.Null(registerInfo, nameof(registerInfo));
            var user = new User { UserName = registerInfo.Username, Email = registerInfo.Email };
            var result = await _userManager.CreateAsync(user, registerInfo.Password);

            if (result.Succeeded) {
                return GenerateJwtToken(user);
            }

            throw new Exception("User registration failed");
        }

        public async Task<string> LoginAsync(LoginInfo loginInfo) {
            Guard.Against.Null(loginInfo, nameof(loginInfo));
            var user = await _userManager.FindByNameAsync(loginInfo.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginInfo.Password)) {
                return GenerateJwtToken(user);
            }

            throw new Exception("Invalid login attempt");
        }

        private string GenerateJwtToken(User user) {
            Guard.Against.Null(user, nameof(user));
            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, user.Id)
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
