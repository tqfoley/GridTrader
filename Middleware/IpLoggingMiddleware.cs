using SchwabOAuthApp.Services;

namespace SchwabOAuthApp.Middleware
{
    public class IpLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IIpLoggerService _ipLogger;

        public IpLoggingMiddleware(RequestDelegate next, IIpLoggerService ipLogger)
        {
            _next = next;
            _ipLogger = ipLogger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Get the IP address from the request
            var ipAddress = GetClientIpAddress(context);

            // Log the IP address asynchronously (fire and forget to not block the request)
            _ = _ipLogger.LogIpAddressAsync(ipAddress);

            // Call the next middleware in the pipeline
            await _next(context);
        }

        private string GetClientIpAddress(HttpContext context)
        {
            // Try to get the real IP from X-Forwarded-For header (if behind a proxy/load balancer)
            var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                // X-Forwarded-For can contain multiple IPs, take the first one
                var ips = forwardedFor.Split(',');
                return ips[0].Trim();
            }

            // Try X-Real-IP header (some proxies use this)
            var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp))
            {
                return realIp;
            }

            // Fall back to RemoteIpAddress
            return context.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
