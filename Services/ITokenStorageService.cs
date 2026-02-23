using SchwabOAuthApp.Models;

namespace SchwabOAuthApp.Services
{
    public interface ITokenStorageService
    {
        void SaveTokens(TokenResponse tokenResponse);
        TokenResponse? LoadTokens();
        void ClearTokens();
        bool HasTokens();
    }
}
