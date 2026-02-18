// dotnet-jwt-login/Services/UserService.cs
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using WebApi.Helpers;

namespace WebApi.Services
{
    public interface IUserService
    {
        string IssueToken(string sub, IEnumerable<string> roles);
        object GetPublicJwks();
    }

    public class UserService : IUserService
    {
        private readonly JwtSettings _settings;

        public UserService(IOptions<JwtSettings> settings)
        {
            _settings = settings.Value;
        }

        public string IssueToken(string sub, IEnumerable<string> roles)
        {
            var rsaParams = LoadPrivateKey();
            var key = new RsaSecurityKey(rsaParams) { KeyId = _settings.KeyId };
            var credentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);

            var now = DateTime.UtcNow;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, sub),
                new Claim(
                    JwtRegisteredClaimNames.Iat,
                    new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64),
            };
            claims.AddRange(roles.Select(r => new Claim("roles", r)));

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer            = _settings.Issuer,
                Audience          = _settings.Audience,
                Subject           = new ClaimsIdentity(claims),
                NotBefore         = now,
                IssuedAt          = now,
                Expires           = now.AddMinutes(_settings.TokenLifetimeMinutes),
                SigningCredentials = credentials,
            };

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(descriptor));
        }

        public object GetPublicJwks()
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(_settings.PrivateKeyPath));

            var pubKey = new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: false))
            {
                KeyId = _settings.KeyId
            };

            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(pubKey);
            jwk.Use = "sig";
            return new { keys = new[] { jwk } };
        }

        // helper: load private key params (struct copy — safe to use after RSA disposal)
        private RSAParameters LoadPrivateKey()
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(_settings.PrivateKeyPath));
            return rsa.ExportParameters(includePrivateParameters: true);
        }
    }
}
