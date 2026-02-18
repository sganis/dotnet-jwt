// iisjwt/Controllers/LoginController.cs
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApi.Services;

namespace WebApi.Controllers
{
    [ApiController]
    [Route("desktop")]
    public class LoginController : ControllerBase
    {
        private readonly IUserService _userService;

        public LoginController(IUserService userService)
        {
            _userService = userService;
        }

        /// <summary>
        /// Exchange a Windows (Negotiate) identity for a signed JWT.
        /// The <c>roles</c> claim contains all AD group sAMAccountNames of the
        /// caller. Role-to-permission mapping is handled downstream by CHAT-PROXY
        /// via its GROUP_ROLE_MAP configuration.
        /// </summary>
        [Authorize]
        [HttpPost("token")]
        [SupportedOSPlatform("windows")]
        public IActionResult Token()
        {
            var name = User.Identity?.Name;
            if (string.IsNullOrEmpty(name))
                return Unauthorized(new { message = "Windows identity unavailable." });

            var parts = name.Split('\\');
            if (parts.Length != 2)
                return Unauthorized(new { message = $"Cannot parse identity '{name}'." });

            var domainName = parts[0];
            var username   = parts[1];

            List<string> groups;
            try
            {
                using var ctx = new PrincipalContext(ContextType.Domain, domainName);
                using var up  = UserPrincipal.FindByIdentity(ctx, IdentityType.SamAccountName, username);

                if (up == null)
                    return Unauthorized(new { message = "User not found in AD." });

                groups = up.GetGroups()
                    .Select(g => g.SamAccountName)
                    .ToList();
            }
            catch (PrincipalServerDownException ex)
            {
                return StatusCode(503, new { message = $"AD unavailable: {ex.Message}" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = $"AD query failed: {ex.Message}" });
            }

            var sub   = $"{domainName}\\{username}";
            var token = _userService.IssueToken(sub, groups);
            return Ok(new { token });
        }
    }
}
