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
    public class UsersController : ControllerBase
    {
        private IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

       

        [AuthorizeJwt]
        [HttpGet]
        public IActionResult GetAll()
        {
            var user = User.Identity.Name;
            var users = _userService.GetAll();
            return Ok(users);
        }
    }
}
