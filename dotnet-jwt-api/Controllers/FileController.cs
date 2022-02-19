using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class FileController : ControllerBase {

        [AllowAnonymous]
        [HttpGet]
        public IActionResult Index() {
            return Ok(new { username = User.Identity.Name});
        }

        [AuthorizeJwt]
        [HttpGet]
        [Route("list")]
        public IActionResult GetFiles(string path) {
            return Ok(new { file = "a_file.txt" });
        }

    }
}
