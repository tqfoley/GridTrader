using System.Text;
using System.Text.Json;
using SchwabOAuthApp.Models;

namespace SchwabOAuthApp.Services
{
    public class SchwabService : ISchwabService
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;

        private const string TokenEndpoint = "https://api.schwabapi.com/v1/oauth/token";

        public SchwabService(IConfiguration configuration, IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
        }

        public async Task<TokenResponse> ExchangeCodeForTokenAsync(string code)
        {
            var clientId = _configuration["Schwab:ClientId"];
            var clientSecret = _configuration["Schwab:ClientSecret"];
            var redirectUri = _configuration["Schwab:RedirectUri"];

            var client = _httpClientFactory.CreateClient();

            var authHeader = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
            client.DefaultRequestHeaders.Add("Authorization", $"Basic {authHeader}");

            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", redirectUri)
            });

            var response = await client.PostAsync(TokenEndpoint, content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Token exchange failed: {responseContent}");
            }

            return JsonSerializer.Deserialize<TokenResponse>(responseContent);
        }

        public async Task<TokenResponse> RefreshAccessTokenAsync(string refreshToken)
        {
            var clientId = _configuration["Schwab:ClientId"];
            var clientSecret = _configuration["Schwab:ClientSecret"];

            var client = _httpClientFactory.CreateClient();

            var authHeader = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}"));
            client.DefaultRequestHeaders.Add("Authorization", $"Basic {authHeader}");

            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("refresh_token", refreshToken)
            });

            var response = await client.PostAsync(TokenEndpoint, content);
            var responseContent = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new Exception($"Token refresh failed: {responseContent}");
            }

            return JsonSerializer.Deserialize<TokenResponse>(responseContent);
        }
    }
}
