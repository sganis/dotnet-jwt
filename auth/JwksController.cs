// auth/JwksController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi
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

        /// <summary>Returns the RSA public keys in JWK Set format for JWT signature verification.</summary>
        [AllowAnonymous]
        [HttpGet("jwks")]
        public IActionResult GetJwks()
        {
            return Ok(_userService.GetPublicJwks());
        }
    }
}
