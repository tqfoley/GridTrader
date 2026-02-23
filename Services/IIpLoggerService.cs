namespace SchwabOAuthApp.Services
{
    public interface IIpLoggerService
    {
        Task LogIpAddressAsync(string ipAddress);
    }
}
