using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
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
        private readonly string profileApiUrl = $"http://poplensUserProfileApi:8080/api/Profile";

        public UserAuthenticationService(UserManager<User> userManager, IConfiguration configuration) {
            _userManager = userManager;
            _configuration = configuration;
        }

        public async Task<string> RegisterAsync(RegisterInfo registerInfo) {
            Guard.Against.Null(registerInfo, nameof(registerInfo));
            var user = new User { UserName = registerInfo.Username, Email = registerInfo.Email };
            var result = await _userManager.CreateAsync(user, registerInfo.Password);

            if (result.Succeeded) {
                var token = GenerateJwtToken(user);

                // Call User Profile API to create a profile
                var profileCreated = await CreateProfileForUserAsync(user.Id); //buraya fallback mekanizması lazım
                if (!profileCreated) {
                    await _userManager.DeleteAsync(user);
                    throw new Exception("User registration succeeded but profile creation failed.");
                }

                return token;
            }

            throw new Exception("User registration failed");
        }

        private async Task<bool> CreateProfileForUserAsync(string userId) {
            Guard.Against.NullOrEmpty(userId, nameof(userId));
            using var client = new HttpClient();

            var content = new StringContent(JsonConvert.SerializeObject(new { UserId = userId }), Encoding.UTF8, "application/json");

            var response = await client.PostAsync($"{profileApiUrl}/{userId}", content);

            return response.IsSuccessStatusCode;
        }

        public async Task<string> LoginAsync(LoginInfo loginInfo) {
            Guard.Against.Null(loginInfo, nameof(loginInfo));
            var user = await _userManager.FindByNameAsync(loginInfo.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, loginInfo.Password)) {
                return GenerateJwtToken(user);
            }

            throw new Exception("Invalid login attempt");
        }

        public async Task<Ids> FetchIdsFromUsername(string username) {
            Guard.Against.NullOrEmpty(username, nameof(username));
            var user = await _userManager.FindByNameAsync(username);
            if (user == null) {
                throw new Exception("User not found from username");
            }
            using var client = new HttpClient();
            var response = await client.GetAsync($"{profileApiUrl}/GetProfileIdWithUserId/{user.Id}");
            if (response.IsSuccessStatusCode) {
                var content = await response.Content.ReadAsStringAsync();
                var profileId = JsonConvert.DeserializeObject<Guid>(content);
                return new Ids {
                    ProfileId = profileId,
                    UserId = user.Id
                };
            }
            throw new Exception("Profile not found for user");
        }

        private string GenerateJwtToken(User user) {
            Guard.Against.Null(user, nameof(user));
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, user.Id)
            };

            DotNetEnv.Env.Load();
            string jwtKey = "moresimplekeyrightherefolkssssssssssssss";
            string issuer = "YourIssuer"; //TODO: docker compose environmentından al
            string audience = "YourAudience";
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<Dictionary<Guid, string>> GetUsernamesByIdsAsync(List<Guid> userIds) {
            Guard.Against.Null(userIds, nameof(userIds));
            var userDictionary = new Dictionary<Guid, string>();

            foreach (var userId in userIds) {
                var user = await _userManager.FindByIdAsync(userId.ToString());
                if (user != null) {
                    userDictionary[userId] = user.UserName;
                }
            }

            return userDictionary;
        }

        public async Task<List<User>> SearchUserByUsernameAsync(string username) {
            Guard.Against.NullOrEmpty(username, nameof(username));

            // Find users whose usernames contain the search term
            var users = await _userManager.Users
                .Where(u => u.UserName.Contains(username))
                .OrderBy(u => u.UserName)
                .Take(8)
                .ToListAsync();

            return users;
        }
    }
}
