namespace SchwabOAuthApp.Models
{
    public class TokenResponse
    {
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public int expires_in { get; set; }
        public string token_type { get; set; }

        public string AccessToken => access_token;
        public string RefreshToken => refresh_token;
        public int ExpiresIn => expires_in;
        public string TokenType => token_type;
        public bool IsExpired { get; set; }
    }
}
