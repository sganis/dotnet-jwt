// auth/LoginController.cs
using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;

namespace WebApi
{
    [ApiController]
    [Route("desktop")]
    public class LoginController : ControllerBase
    {
        private readonly IUserService _userService;
        private readonly ILogger<LoginController> _logger;

        private const int AdTimeoutSeconds = 5;

        public LoginController(IUserService userService, ILogger<LoginController> logger)
        {
            _userService = userService;
            _logger      = logger;
        }

        /// <summary>
        /// Exchange a Windows (Negotiate) identity for a signed JWT.
        /// The caller authenticates via NTLM/Kerberos — no credentials in the body.
        /// The <c>groups</c> claim contains the AD group sAMAccountNames of the caller.
        /// Access and rate-limit tier are enforced downstream by CHAT-PROXY.
        /// </summary>
        [EnableRateLimiting("token")]
        [Authorize]
        [HttpPost("token")]
        [SupportedOSPlatform("windows")]
        public async Task<IActionResult> Token()
        {
            var name = User.Identity?.Name;
            if (string.IsNullOrEmpty(name))
            {
                _logger.LogWarning("Token request with empty Windows identity.");
                return Unauthorized(new { message = "Authentication failed." });
            }

            var parts = name.Split('\\');
            var domainName = parts.Length == 2 ? parts[0] : null;
            var username   = parts.Length == 2 ? parts[1] : null;

            if (string.IsNullOrWhiteSpace(domainName) || string.IsNullOrWhiteSpace(username))
            {
                _logger.LogWarning("Token request with unparseable Windows identity.");
                return Unauthorized(new { message = "Authentication failed." });
            }

            List<string> groups;
            try
            {
                // Wrap synchronous AD calls in a task with a hard timeout.
                var adTask = Task.Run(() =>
                {
                    using var ctx = new PrincipalContext(ContextType.Domain, domainName);
                    using var up  = UserPrincipal.FindByIdentity(
                        ctx, IdentityType.SamAccountName, username);

                    return up?.GetGroups()
                              .Select(g => g.SamAccountName)
                              .ToList();
                });

                var result = await adTask.WaitAsync(TimeSpan.FromSeconds(AdTimeoutSeconds));

                if (result == null)
                {
                    _logger.LogWarning("AD user not found: {Domain}\\{Username}",
                        domainName, username);
                    return Unauthorized(new { message = "Authentication failed." });
                }

                groups = result;
            }
            catch (TimeoutException)
            {
                _logger.LogError("AD query timed out for {Domain}\\{Username}",
                    domainName, username);
                return StatusCode(503, new { message = "Directory service unavailable." });
            }
            catch (PrincipalServerDownException ex)
            {
                _logger.LogError(ex, "AD server down during token request.");
                return StatusCode(503, new { message = "Directory service unavailable." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "AD query failed for {Domain}\\{Username}",
                    domainName, username);
                return StatusCode(500, new { message = "Authentication failed." });
            }

            var sub = $"{domainName}\\{username}";
            _logger.LogInformation("Token issued for {Sub}", sub);

            return Ok(_userService.IssueToken(sub, groups));
        }
    }
}
