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
        [HttpGet("ProtectedData")]
        public IActionResult ProtectedData() {
            return Ok(new { Message = "You have access to this protected endpoint." });
        }
    }
}
