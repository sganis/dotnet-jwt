// dotnet-jwt-login/Helpers/JwtSettings.cs
namespace WebApi.Helpers
{
    public class JwtSettings
    {
        public string Issuer { get; set; } = "https://seecloud-iis.company.local";
        public string Audience { get; set; } = "orion-chat-proxy";
        /// <summary>Path to the RSA private key PEM file (e.g. C:\Keys\seecloud-jwt.pem).</summary>
        public string PrivateKeyPath { get; set; }
        /// <summary>kid value embedded in the JWT header and JWKS response.</summary>
        public string KeyId { get; set; } = "seecloud-1";
        public int TokenLifetimeMinutes { get; set; } = 30;
    }
}
