namespace SchwabOAuthApp.Models
{
    public class TotpSetupViewModel
    {
        public string Secret { get; set; } = string.Empty;
        public string QrCodeBase64 { get; set; } = string.Empty;
        public string ManualEntryKey { get; set; } = string.Empty;
    }
}
