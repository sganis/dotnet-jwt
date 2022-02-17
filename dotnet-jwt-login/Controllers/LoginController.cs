using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApi.Entities;
using WebApi.Models;
using WebApi.Services;

namespace WebApi.Controllers
{
    //[Authorize]
    [ApiController]
    [Route("[controller]")]
    public class LoginController : ControllerBase
    {
        private IUserService _userService;

        public LoginController(IUserService userService)
        {
            _userService = userService;
        }

        [Authorize]
        [HttpGet]
        public IActionResult Authenticate() {
            var identity = User.Identity.Name.Split("\\");
            if (identity.Length < 2)
                return BadRequest(new { message = "Client not authenticated" });

            User user = new User {  Username = identity[1] };
            var response = _userService.Authenticate(user);

            if (response == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            return Ok(response);
        }

        [Authorize]
        [HttpPost]
        public IActionResult Authenticate(AuthenticateRequest req) {
            var identity = User.Identity.Name.Split("\\");
            if (identity.Length < 2)
                return BadRequest(new { message = "Client not authenticated" });

            User user = new User { Username = identity[1] };
            var response = _userService.Authenticate(user);

            if (response == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            return Ok(response);
        }

    }
}
