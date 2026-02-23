namespace SchwabOAuthApp.Services
{
    public class IpLoggerService : IIpLoggerService
    {
        private readonly string _logFilePath;
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        private HashSet<string> _loggedIps;

        public IpLoggerService()
        {
            _logFilePath = Path.Combine(Directory.GetCurrentDirectory(), "visitor_ips.txt");
            _loggedIps = new HashSet<string>();
            LoadExistingIps();
        }

        private void LoadExistingIps()
        {
            try
            {
                if (File.Exists(_logFilePath))
                {
                    var lines = File.ReadAllLines(_logFilePath);
                    _loggedIps = new HashSet<string>(lines);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading existing IPs: {ex.Message}");
            }
        }

        public async Task LogIpAddressAsync(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return;

            // Normalize the IP address (remove port if present)
            var normalizedIp = ipAddress.Contains(':') ? ipAddress.Split(':')[0] : ipAddress;

            await _semaphore.WaitAsync();
            try
            {
                // Check if IP is already logged
                if (_loggedIps.Contains(normalizedIp))
                    return;

                // Add to in-memory set
                _loggedIps.Add(normalizedIp);

                // Append to file
                await File.AppendAllTextAsync(_logFilePath, normalizedIp + Environment.NewLine);

                Console.WriteLine($"Logged new IP address: {normalizedIp}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error logging IP address: {ex.Message}");
            }
            finally
            {
                _semaphore.Release();
            }
        }
    }
}
