// iisjwt/JwtSettings.cs
using System.Collections.Generic;

namespace WebApi
{
    /// <summary>Maps a certificate thumbprint to its stable kid identifier in JWKS.</summary>
    public class JwksCertEntry
    {
        /// <summary>Certificate thumbprint in LocalMachine\My (hex, case-insensitive, spaces ignored).</summary>
        public string Thumbprint { get; set; } = "";

        /// <summary>Stable kid value published in JWKS and matched against JWT header.kid.</summary>
        public string Kid { get; set; } = "";
    }

    public class JwtSettings
    {
        public string Issuer { get; set; } = "https://seecloud-iis.company.local";
        public string Audience { get; set; } = "orion-chat-proxy";

        /// <summary>kid placed in the header of newly issued JWTs.</summary>
        public string ActiveKid { get; set; } = "";

        /// <summary>Thumbprint of the cert whose private key signs new tokens.</summary>
        public string ActiveSigningThumbprint { get; set; } = "";

        /// <summary>
        /// All certs whose public keys are published in the JWKS endpoint.
        /// Include both the active cert and any previous certs still within the overlap window.
        /// </summary>
        public List<JwksCertEntry> JwksCerts { get; set; } = new();

        public int TokenLifetimeMinutes { get; set; } = 30;
    }
}
