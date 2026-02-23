using SchwabOAuthApp.Models;
using System.Text.Json;

namespace SchwabOAuthApp.Services
{
    public class TokenStorageService : ITokenStorageService
    {
        private readonly string _tokenFilePath;

        public TokenStorageService(IConfiguration configuration)
        {
            var tokenPath = configuration["Schwab:TokenFilePath"] ?? "schwab_tokens.json";
            _tokenFilePath = Path.Combine(Directory.GetCurrentDirectory(), tokenPath);
        }

        public void SaveTokens(TokenResponse tokenResponse)
        {
            try
            {
                var tokenData = new
                {
                    AccessToken = tokenResponse.AccessToken,
                    RefreshToken = tokenResponse.RefreshToken,
                    ExpiresIn = tokenResponse.ExpiresIn,
                    TokenType = tokenResponse.TokenType,
                    SavedAt = DateTime.UtcNow
                };

                var json = JsonSerializer.Serialize(tokenData, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                File.WriteAllText(_tokenFilePath, json);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving tokens: {ex.Message}");
            }
        }

        public TokenResponse? LoadTokens()
        {
            try
            {
                if (!File.Exists(_tokenFilePath))
                {
                    return null;
                }

                var json = File.ReadAllText(_tokenFilePath);
                var tokenData = JsonSerializer.Deserialize<SavedTokenData>(json);

                if (tokenData == null)
                {
                    return null;
                }

                // Check if access token has expired (with 5 minute buffer)
                var tokenAge = DateTime.UtcNow - tokenData.SavedAt;
                var isExpired = tokenAge.TotalSeconds > (tokenData.ExpiresIn - 300);

                return new TokenResponse
                {
                    access_token = tokenData.AccessToken,
                    refresh_token = tokenData.RefreshToken,
                    expires_in = tokenData.ExpiresIn,
                    token_type = tokenData.TokenType,
                    IsExpired = isExpired
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading tokens: {ex.Message}");
                return null;
            }
        }

        public void ClearTokens()
        {
            try
            {
                if (File.Exists(_tokenFilePath))
                {
                    File.Delete(_tokenFilePath);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error clearing tokens: {ex.Message}");
            }
        }

        public bool HasTokens()
        {
            return File.Exists(_tokenFilePath);
        }

        private class SavedTokenData
        {
            public string AccessToken { get; set; } = string.Empty;
            public string RefreshToken { get; set; } = string.Empty;
            public int ExpiresIn { get; set; }
            public string TokenType { get; set; } = string.Empty;
            public DateTime SavedAt { get; set; }
        }
    }
}
