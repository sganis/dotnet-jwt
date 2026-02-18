// iisjwt/UserService.cs
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WebApi
{
    public interface IUserService
    {
        TokenResponse IssueToken(string sub, IEnumerable<string> groups);
        object GetPublicJwks();
    }

    public class UserService : IUserService
    {
        private readonly JwtSettings _settings;

        public UserService(IOptions<JwtSettings> settings)
        {
            _settings = settings.Value;
        }

        public TokenResponse IssueToken(string sub, IEnumerable<string> groups)
        {
            // Export RSA params immediately so the cert and RSA objects can be disposed.
            var rsaParams  = LoadPrivateKeyParams(_settings.ActiveSigningThumbprint);
            var signingKey = new RsaSecurityKey(rsaParams) { KeyId = _settings.ActiveKid };
            var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256);

            var now = DateTime.UtcNow;
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, sub),
                new Claim(
                    JwtRegisteredClaimNames.Iat,
                    new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64),
            };
            // Each AD group becomes a separate "groups" claim.
            // JwtSecurityTokenHandler serialises multiple same-named claims as a JSON array.
            claims.AddRange(groups.Select(g => new Claim("groups", g)));

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
            var token   = handler.WriteToken(handler.CreateToken(descriptor));

            return new TokenResponse
            {
                AccessToken = token,
                ExpiresIn   = _settings.TokenLifetimeMinutes * 60,
            };
        }

        public object GetPublicJwks()
        {
            var keys = new List<JsonWebKey>();

            foreach (var entry in _settings.JwksCerts)
            {
                var pubParams = LoadPublicKeyParams(entry.Thumbprint);
                var secKey    = new RsaSecurityKey(pubParams) { KeyId = entry.Kid };
                var jwk       = JsonWebKeyConverter.ConvertFromRSASecurityKey(secKey);
                jwk.Use = "sig";
                keys.Add(jwk);
            }

            return new { keys };
        }

        // ── startup validation ───────────────────────────────────────────────

        /// <summary>
        /// Called at app startup to verify the signing cert exists and the process
        /// has access to its private key. Throws on any failure so the app won't start.
        /// </summary>
        public static void ValidateSigningCert(string thumbprint) =>
            LoadPrivateKeyParams(thumbprint);

        // ── private helpers ──────────────────────────────────────────────────

        /// <summary>
        /// Opens LocalMachine\My, finds the cert by thumbprint, and exports the RSA private
        /// key parameters as a value-type struct so the cert and RSA objects can be safely disposed.
        /// </summary>
        internal static RSAParameters LoadPrivateKeyParams(string thumbprint)
        {
            var clean = NormalizeThumbprint(thumbprint);
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Find(
                X509FindType.FindByThumbprint, clean, validOnly: false);

            if (certs.Count == 0)
                throw new InvalidOperationException(
                    $"Signing cert not found in LocalMachine\\My: {clean}");

            using var cert = certs[0];
            if (!cert.HasPrivateKey)
                throw new InvalidOperationException(
                    $"Cert {clean} has no accessible private key — check IIS app pool ACL.");

            using var rsa = cert.GetRSAPrivateKey()
                ?? throw new InvalidOperationException(
                    $"Cert {clean} does not have an RSA private key.");

            return rsa.ExportParameters(includePrivateParameters: true);
        }

        /// <summary>Exports public RSA key parameters. No private key access required.</summary>
        private static RSAParameters LoadPublicKeyParams(string thumbprint)
        {
            var clean = NormalizeThumbprint(thumbprint);
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            var certs = store.Certificates.Find(
                X509FindType.FindByThumbprint, clean, validOnly: false);

            if (certs.Count == 0)
                throw new InvalidOperationException(
                    $"JWKS cert not found in LocalMachine\\My: {clean}");

            using var cert = certs[0];
            using var rsa  = cert.GetRSAPublicKey()
                ?? throw new InvalidOperationException(
                    $"Cert {clean} does not have an RSA public key.");

            return rsa.ExportParameters(includePrivateParameters: false);
        }

        private static string NormalizeThumbprint(string t) =>
            t.Replace(" ", "").ToUpperInvariant();
    }
}
