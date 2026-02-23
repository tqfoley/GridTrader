using OtpNet;
using QRCoder;
using System.Text;

namespace SchwabOAuthApp.Services
{
    public class TotpService : ITotpService
    {
        private readonly string _secretFilePath;

        public TotpService(IConfiguration configuration)
        {
            var dataPath = configuration["Totp:SecretFilePath"] ?? "totp_secret.txt";
            _secretFilePath = Path.Combine(Directory.GetCurrentDirectory(), dataPath);
        }

        public string GenerateSecret()
        {
            var key = KeyGeneration.GenerateRandomKey(20);
            return Base32Encoding.ToString(key);
        }

        public string GetQrCodeUri(string secret, string issuer, string user)
        {
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(user)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}";
        }

        public byte[] GenerateQrCodeImage(string qrCodeUri)
        {
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            return qrCode.GetGraphic(20);
        }

        public bool VerifyCode(string secret, string code)
        {
            if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(code))
                return false;

            try
            {
                var secretBytes = Base32Encoding.ToBytes(secret);
                var totp = new Totp(secretBytes);

                // Allow a window of 1 step before and after (30 seconds each)
                return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
            }
            catch
            {
                return false;
            }
        }

        public void SaveSecret(string secret)
        {
            File.WriteAllText(_secretFilePath, secret);
        }

        public string? GetSavedSecret()
        {
            if (File.Exists(_secretFilePath))
            {
                return File.ReadAllText(_secretFilePath).Trim();
            }
            return null;
        }

        public bool IsSetup()
        {
            return File.Exists(_secretFilePath) && !string.IsNullOrEmpty(GetSavedSecret());
        }
    }
}
