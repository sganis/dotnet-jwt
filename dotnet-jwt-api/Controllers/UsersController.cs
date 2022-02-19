using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApi.Entities;
using WebApi.Models;
using WebApi.Services;

namespace WebApi.Controllers
{
    [AuthorizeJwt]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }
               

        [HttpGet]
        public IActionResult GetAll()
        {
            var user = User.Identity.Name;
            var users = _userService.GetAll();
            return Ok(users);
        }
    }
}
