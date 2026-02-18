// iisjwt/TokenResponse.cs
using System.Text.Json.Serialization;

namespace WebApi
{
    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; init; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; init; } = "Bearer";

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; init; }
    }
}
