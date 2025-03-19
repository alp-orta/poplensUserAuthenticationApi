using Ardalis.GuardClauses;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using poplensUserAuthenticationApi.Contracts;
using poplensUserAuthenticationApi.Models.Dtos;

namespace poplensUserAuthenticationApi.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    public class UserAuthenticationController : ControllerBase {
        private readonly IUserAuthenticationService _userAuthenticationService;

        public UserAuthenticationController(IUserAuthenticationService userAuthenticationService) {
            Guard.Against.Null(userAuthenticationService, nameof(userAuthenticationService));
            _userAuthenticationService = userAuthenticationService;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterInfo registerInfo) {
            Guard.Against.Null(registerInfo, nameof(registerInfo));
            var token = await _userAuthenticationService.RegisterAsync(registerInfo);
            return Ok(new { Token = token });
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginInfo loginInfo) {
            Guard.Against.Null(loginInfo, nameof(loginInfo));
            var token = await _userAuthenticationService.LoginAsync(loginInfo);
            var ids = await _userAuthenticationService.FetchIdsFromUsername(loginInfo.UserName);
            return Ok(new { Token = token, UserId = ids.UserId, ProfileId = ids.ProfileId });
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("FetchIdsFromUsername/{username}")]
        public async Task<IActionResult> FetchIdsFromUsername(string username) {
            Guard.Against.NullOrEmpty(username, nameof(username));
            var ids = await _userAuthenticationService.FetchIdsFromUsername(username);
            return Ok(new { UserId = ids.UserId, ProfileId = ids.ProfileId });
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpGet("ProtectedData")]
        public IActionResult ProtectedData() {
            return Ok(new { Message = "You have access to this protected endpoint." });
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPost("GetUsernamesByIdsAsync")]
        public async Task<IActionResult> GetUsernamesByIdsAsync([FromBody] List<Guid> userIds) {
            if (userIds == null || userIds.Count == 0) {
                return BadRequest("User IDs cannot be null or empty.");
            }

            var userDictionary = await _userAuthenticationService.GetUsernamesByIdsAsync(userIds);
            return Ok(userDictionary);
        }
    }
}
