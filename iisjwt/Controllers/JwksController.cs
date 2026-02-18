// dotnet-jwt-login/Controllers/JwksController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApi.Services;

namespace WebApi.Controllers
{
    [ApiController]
    [Route("desktop")]
    public class JwksController : ControllerBase
    {
        private readonly IUserService _userService;

        public JwksController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary>Returns the RSA public key in JWK Set format for JWT signature verification.</summary>
        [AllowAnonymous]
        [HttpGet("jwks")]
        public IActionResult GetJwks()
        {
            return Ok(_userService.GetPublicJwks());
        }
    }
}
