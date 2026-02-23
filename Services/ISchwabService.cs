namespace SchwabOAuthApp.Services
{
    public interface ISchwabService
    {
        Task<Models.TokenResponse> ExchangeCodeForTokenAsync(string code);
        Task<Models.TokenResponse> RefreshAccessTokenAsync(string refreshToken);
    }
}
