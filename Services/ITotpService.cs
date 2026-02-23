namespace SchwabOAuthApp.Services
{
    public interface ITotpService
    {
        string GenerateSecret();
        string GetQrCodeUri(string secret, string issuer, string user);
        byte[] GenerateQrCodeImage(string qrCodeUri);
        bool VerifyCode(string secret, string code);
        void SaveSecret(string secret);
        string? GetSavedSecret();
        bool IsSetup();
    }
}
