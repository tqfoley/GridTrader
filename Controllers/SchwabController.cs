using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;
using SchwabOAuthApp.Models;
using MyApi.Services;

namespace SchwabOAuthApp.Controllers
{
    public class SchwabController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly SchwabOAuthApp.Services.ITotpService _totpService;
        private readonly SchwabOAuthApp.Services.ITokenStorageService _tokenStorage;
        private readonly SchwabOrderService _orderService;

        // Schwab OAuth endpoints
        private const string AuthorizationEndpoint = "https://api.schwabapi.com/v1/oauth/authorize";
        private const string TokenEndpoint = "https://api.schwabapi.com/v1/oauth/token";

        // Schwab API base URL
        private const string ApiBaseUrl = "https://api.schwabapi.com/trader/v1";

        public SchwabController(IConfiguration configuration, IHttpClientFactory httpClientFactory, SchwabOAuthApp.Services.ITotpService totpService, SchwabOAuthApp.Services.ITokenStorageService tokenStorage, SchwabOrderService orderService)
        {
            _configuration = configuration;
            _httpClientFactory = httpClientFactory;
            _totpService = totpService;
            _tokenStorage = tokenStorage;
            _orderService = orderService;
        }

        public IActionResult Login()
        {
            // Check if TOTP is set up
            if (_totpService.IsSetup())
            {
                // Check if user is already verified
                var totpVerified = HttpContext.Session.GetString("totp_verified");
                if (totpVerified != "true")
                {
                    return RedirectToAction("TotpVerify");
                }
            }
            else
            {
                // If TOTP is not set up, redirect to setup
                return RedirectToAction("TotpSetup");
            }

            return View();
        }

        [HttpGet]
        public IActionResult TotpSetup()
        {
            // Prevent reconfiguration if TOTP is already set up
            if (_totpService.IsSetup())
            {
                TempData["Error"] = "TOTP is already configured and cannot be reconfigured. If you need to reset it, please delete the secret file manually.";
                return RedirectToAction("Dashboard");
            }

            // Reuse existing secret if available, otherwise generate new one
            var secret = HttpContext.Session.GetString("temp_totp_secret");
            if (string.IsNullOrEmpty(secret))
            {
                secret = _totpService.GenerateSecret();
                HttpContext.Session.SetString("temp_totp_secret", secret);
            }

            var issuer = _configuration["Totp:Issuer"] ?? "SchwabApp";
            var user = "admin";

            var qrCodeUri = _totpService.GetQrCodeUri(secret, issuer, user);
            var qrCodeImage = _totpService.GenerateQrCodeImage(qrCodeUri);

            var model = new TotpSetupViewModel
            {
                Secret = secret,
                QrCodeBase64 = Convert.ToBase64String(qrCodeImage),
                ManualEntryKey = secret
            };

            return View(model);
        }

        [HttpPost]
        public IActionResult ConfirmSetup(string code)
        {
            // Prevent reconfiguration if TOTP is already set up
            if (_totpService.IsSetup())
            {
                TempData["Error"] = "TOTP is already configured and cannot be reconfigured.";
                return RedirectToAction("Dashboard");
            }

            var tempSecret = HttpContext.Session.GetString("temp_totp_secret");

            if (string.IsNullOrEmpty(tempSecret))
            {
                TempData["Error"] = "Setup session expired. Please start again.";
                return RedirectToAction("TotpSetup");
            }

            if (_totpService.VerifyCode(tempSecret, code))
            {
                // Save the secret permanently
                _totpService.SaveSecret(tempSecret);
                HttpContext.Session.Remove("temp_totp_secret");
                HttpContext.Session.SetString("totp_verified", "true");

                TempData["Success"] = "Google Authenticator setup successful!";
                return RedirectToAction("Dashboard");
            }
            else
            {
                TempData["Error"] = "Invalid code. Please try again.";
                return RedirectToAction("TotpSetup");
            }
        }

        [HttpGet]
        public IActionResult TotpVerify()
        {
            return View();
        }

        [HttpPost]
        public IActionResult VerifyTotpCode(string code)
        {
            var secret = _totpService.GetSavedSecret();

            if (string.IsNullOrEmpty(secret))
            {
                return RedirectToAction("TotpSetup");
            }

            if (_totpService.VerifyCode(secret, code))
            {
                HttpContext.Session.SetString("totp_verified", "true");
                return RedirectToAction("Dashboard");
            }
            else
            {
                ViewBag.Error = "Invalid authenticator code. Please try again.";
                return View("TotpVerify");
            }
        }

        [HttpGet]
        public IActionResult Authorize()
        {
            var clientId = _configuration["Schwab:ClientId"];
            var redirectUri = _configuration["Schwab:RedirectUri"];

            var authUrl = $"{AuthorizationEndpoint}?" +
                $"client_id={Uri.EscapeDataString(clientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}";

            return Redirect(authUrl);
        }

        [HttpGet]
        public async Task<IActionResult> Callback(string code)
        {
            if (string.IsNullOrEmpty(code))
            {
                return BadRequest("Authorization code not received");
            }

            try
            {
                // Exchange authorization code for access token
                var tokenResponse = await ExchangeCodeForTokenAsync(code);

                // Store tokens in session
                HttpContext.Session.SetString("access_token", tokenResponse.AccessToken);
                HttpContext.Session.SetString("refresh_token", tokenResponse.RefreshToken);
                HttpContext.Session.SetInt32("expires_in", tokenResponse.ExpiresIn);

                // Save tokens to file for persistence
                _tokenStorage.SaveTokens(tokenResponse);

                return RedirectToAction("Dashboard");
            }
            catch (Exception ex)
            {
                TempData["Error"] = $"Error during token exchange: {ex.Message}";
                return RedirectToAction("Login");
            }
        }

        public async Task<IActionResult> Dashboard()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);

            // Get failed attempts from session
            var failedAttemptsJson = HttpContext.Session.GetString("failed_attempts");
            var failedAttempts = new List<string>();
            if (!string.IsNullOrEmpty(failedAttemptsJson))
            {
                try
                {
                    failedAttempts = JsonSerializer.Deserialize<List<string>>(failedAttemptsJson) ?? new List<string>();
                }
                catch { }
            }
            ViewBag.FailedAttempts = failedAttempts;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = HttpContext.Session.GetString("refresh_token");

            // If no refresh token in session, try to load from file
            if (string.IsNullOrEmpty(refreshToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    refreshToken = storedTokens.RefreshToken;
                }
                else
                {
                    return BadRequest("No refresh token available");
                }
            }

            try
            {
                var tokenResponse = await RefreshAccessTokenAsync(refreshToken);

                HttpContext.Session.SetString("access_token", tokenResponse.AccessToken);
                HttpContext.Session.SetString("refresh_token", tokenResponse.RefreshToken);
                HttpContext.Session.SetInt32("expires_in", tokenResponse.ExpiresIn);

                // Save refreshed tokens to file
                _tokenStorage.SaveTokens(tokenResponse);

                return Ok("Token refreshed successfully");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error refreshing token: {ex.Message}");
            }
        }

        [HttpPost]
        public async Task<IActionResult> Disconnect()
        {
            // Clear session and stored tokens
            HttpContext.Session.Clear();
            _tokenStorage.ClearTokens();
            return RedirectToAction("Login");
        }

        public async Task<IActionResult> Orders()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        public async Task<IActionResult> TransactionHistory()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        public async Task<IActionResult> GridPairsHistory()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        [HttpGet]
        public async Task<IActionResult> GetAccountNumbers(string password = "")
        {
            // Check password
            if (!CheckPassword(password, "GetAccountNumbers"))
            {
                return Unauthorized("Invalid password");
            }

            var accessToken = await GetValidAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                var apiUrl = $"{ApiBaseUrl}/accounts/accountNumbers";
                var response = await client.GetAsync(apiUrl);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return Content(content, "application/json");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, errorContent);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetAccountDetails(string accountHash, string password = "")
        {
            // Check password
            if (!CheckPassword(password, "GetAccountDetails"))
            {
                return Unauthorized("Invalid password");
            }

            var accessToken = await GetValidAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            if (string.IsNullOrEmpty(accountHash))
            {
                return BadRequest("Account hash is required");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Get account details with positions
                var apiUrl = $"{ApiBaseUrl}/accounts/{accountHash}?fields=positions";
                var response = await client.GetAsync(apiUrl);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return Content(content, "application/json");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, errorContent);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetOrders(string accountHash, string password = "")
        {
            // Check password
            if (!CheckPassword(password, "GetOrders"))
            {
                return Unauthorized("Invalid password");
            }

            var accessToken = await GetValidAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            if (string.IsNullOrEmpty(accountHash))
            {
                return BadRequest("Account hash is required");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Get orders for the account - filter by status if needed
                // Available statuses: AWAITING_PARENT_ORDER, AWAITING_CONDITION, AWAITING_STOP_CONDITION,
                // AWAITING_MANUAL_REVIEW, ACCEPTED, AWAITING_UR_OUT, PENDING_ACTIVATION, QUEUED, WORKING,
                // REJECTED, PENDING_CANCEL, CANCELED, PENDING_REPLACE, REPLACED, FILLED, EXPIRED, NEW,
                // AWAITING_RELEASE_TIME, PENDING_ACKNOWLEDGEMENT, PENDING_RECALL, UNKNOWN

                // Get only open/working orders from the last 60 days
                // Schwab API expects ISO 8601 format: yyyy-MM-ddTHH:mm:ss.fffZ
                var fromDate = DateTime.UtcNow.AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var toDate = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

                // Get all orders (removed status=WORKING filter to see all statuses)
                var apiUrl = $"{ApiBaseUrl}/accounts/{accountHash}/orders?fromEnteredTime={Uri.EscapeDataString(fromDate)}&toEnteredTime={Uri.EscapeDataString(toDate)}";
                var response = await client.GetAsync(apiUrl);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return Content(content, "application/json");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, errorContent);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        [HttpDelete]
        public async Task<IActionResult> CancelOrder(string accountHash, string orderId, string password = "")
        {
            // Check password
            if (!CheckPassword(password, "CancelOrder"))
            {
                return Unauthorized("Invalid password");
            }

            var accessToken = await GetValidAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            if (string.IsNullOrEmpty(accountHash) || string.IsNullOrEmpty(orderId))
            {
                return BadRequest("Account hash and order ID are required");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Delete the order
                var apiUrl = $"{ApiBaseUrl}/accounts/{accountHash}/orders/{orderId}";
                var response = await client.DeleteAsync(apiUrl);

                if (response.IsSuccessStatusCode)
                {
                    return Ok(new { success = true, message = "Order cancelled successfully" });
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, new { success = false, message = errorContent });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { success = false, message = $"Error: {ex.Message}" });
            }
        }

        [HttpGet]
        public async Task<IActionResult> GetTransactionHistory(string accountHash, string password = "", int days = 5)
        {
            // Check password
            if (!CheckPassword(password, "GetTransactionHistory"))
            {
                return Unauthorized("Invalid password");
            }

            var accessToken = await GetValidAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            if (string.IsNullOrEmpty(accountHash))
            {
                return BadRequest("Account hash is required");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Get transactions for the specified number of days (default 5)
                // Schwab API expects ISO 8601 format: yyyy-MM-ddTHH:mm:ss.fffZ
                var startDate = DateTime.UtcNow.AddDays(-days).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var endDate = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

                var apiUrl = $"{ApiBaseUrl}/accounts/{accountHash}/transactions?startDate={Uri.EscapeDataString(startDate)}&endDate={Uri.EscapeDataString(endDate)}";
                var response = await client.GetAsync(apiUrl);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return Content(content, "application/json");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, errorContent);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets potential QBTS orders based on hardcoded buy/sell price pairs.
        /// For each pair, finds most recent buy and sell transactions, determines which order to place next,
        /// and filters out any that already exist as open orders.
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> GetQbtsPendingOrders(string accountHash, string password = "")
        {
            // Check password
            if (!CheckPassword(password, "GetQbtsPendingOrders"))
            {
                return Unauthorized("Invalid password");
            }

            var accessToken = await GetValidAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            if (string.IsNullOrEmpty(accountHash))
            {
                return BadRequest("Account hash is required");
            }

            const string SYMBOL = "QBTS";
            const decimal QUANTITY = 10m;

            // Hardcoded buy/sell price pairs for QBTS
            var pricePairs = new List<(decimal buyPrice, decimal sellPrice)>();
            for (decimal buyPrice = 23.67m; buyPrice <= 31.17m; buyPrice += 0.50m)
            {
                decimal sellPrice = buyPrice + 0.78m; // sell price is 0.78 higher than buy price
                pricePairs.Add((buyPrice, sellPrice));
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Get open orders (WORKING status) from last 60 days
                var ordersFromDate = DateTime.UtcNow.AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var ordersToDate = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var ordersUrl = $"{ApiBaseUrl}/accounts/{accountHash}/orders?fromEnteredTime={Uri.EscapeDataString(ordersFromDate)}&toEnteredTime={Uri.EscapeDataString(ordersToDate)}&status=WORKING";

                // Get transactions from last 7 days
                var transStartDate = DateTime.UtcNow.AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var transEndDate = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
                var transUrl = $"{ApiBaseUrl}/accounts/{accountHash}/transactions?startDate={Uri.EscapeDataString(transStartDate)}&endDate={Uri.EscapeDataString(transEndDate)}";

                // Fetch both in parallel
                var ordersTask = client.GetAsync(ordersUrl);
                var transTask = client.GetAsync(transUrl);

                await Task.WhenAll(ordersTask, transTask);

                var ordersResponse = await ordersTask;
                var transResponse = await transTask;

                if (!ordersResponse.IsSuccessStatusCode)
                {
                    var errorContent = await ordersResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)ordersResponse.StatusCode, $"Orders error: {errorContent}");
                }

                if (!transResponse.IsSuccessStatusCode)
                {
                    var errorContent = await transResponse.Content.ReadAsStringAsync();
                    return StatusCode((int)transResponse.StatusCode, $"Transactions error: {errorContent}");
                }

                var ordersJson = await ordersResponse.Content.ReadAsStringAsync();
                var transJson = await transResponse.Content.ReadAsStringAsync();

                // Parse JSON
                var orders = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(ordersJson);
                var transactions = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(transJson);

                // Build a list of open orders for quick lookup (price -> instruction)
                var openOrders = new List<(decimal price, string instruction)>();
                if (orders.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var order in orders.EnumerateArray())
                    {
                        var orderPrice = order.TryGetProperty("price", out var priceEl) ? priceEl.GetDecimal() : 0m;

                        if (!order.TryGetProperty("orderLegCollection", out var orderLegs) ||
                            orderLegs.ValueKind != System.Text.Json.JsonValueKind.Array)
                            continue;

                        foreach (var leg in orderLegs.EnumerateArray())
                        {
                            var orderQuantity = leg.TryGetProperty("quantity", out var qtyEl) ? qtyEl.GetDecimal() : 0m;
                            var orderInstruction = leg.TryGetProperty("instruction", out var instrEl) ? instrEl.GetString() ?? "" : "";

                            if (!leg.TryGetProperty("instrument", out var instrument))
                                continue;

                            var orderSymbol = instrument.TryGetProperty("symbol", out var symEl) ? symEl.GetString() : "";

                            // Only consider QBTS with quantity 25
                            if (orderSymbol == SYMBOL && orderQuantity == QUANTITY)
                            {
                                openOrders.Add((orderPrice, orderInstruction));
                            }
                        }
                    }
                }

                // Build a dictionary of most recent transactions by price
                // Key: price (rounded to 2 decimals), Value: (time, isBuy)
                var recentTransactions = new Dictionary<decimal, (DateTime time, bool isBuy)>();

                if (transactions.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var trans in transactions.EnumerateArray())
                    {
                        if (!trans.TryGetProperty("transferItems", out var transferItems) ||
                            transferItems.ValueKind != System.Text.Json.JsonValueKind.Array)
                            continue;

                        var transTime = trans.TryGetProperty("time", out var timeEl) ? timeEl.GetString() : null;
                        if (string.IsNullOrEmpty(transTime) || !DateTime.TryParse(transTime, out var parsedTime))
                            continue;

                        foreach (var item in transferItems.EnumerateArray())
                        {
                            if (!item.TryGetProperty("instrument", out var transInstrument))
                                continue;

                            var transSymbol = transInstrument.TryGetProperty("symbol", out var tSymEl) ? tSymEl.GetString() : "";
                            var transQuantity = item.TryGetProperty("amount", out var tQtyEl) ? tQtyEl.GetDecimal() : 0m;
                            var transPrice = item.TryGetProperty("price", out var tPriceEl) ? tPriceEl.GetDecimal() : 0m;

                            // Only consider QBTS with quantity 25
                            if (transSymbol != SYMBOL || Math.Abs(transQuantity) != QUANTITY)
                                continue;

                            var roundedPrice = Math.Round(transPrice, 2);
                            var isBuy = transQuantity > 0;

                            // Keep the most recent transaction for this price
                            if (!recentTransactions.ContainsKey(roundedPrice) || parsedTime > recentTransactions[roundedPrice].time)
                            {
                                recentTransactions[roundedPrice] = (parsedTime, isBuy);
                            }
                        }
                    }
                }

                // Process each price pair and determine what order to place
                var pendingOrders = new List<object>();

                foreach (var (buyPrice, sellPrice) in pricePairs)
                {
                    // Find most recent buy transaction at buyPrice
                    DateTime? buyTransTime = null;
                    if (recentTransactions.TryGetValue(buyPrice, out var buyTrans) && buyTrans.isBuy)
                    {
                        buyTransTime = buyTrans.time;
                    }

                    // Find most recent sell transaction at sellPrice
                    DateTime? sellTransTime = null;
                    if (recentTransactions.TryGetValue(sellPrice, out var sellTrans) && !sellTrans.isBuy)
                    {
                        sellTransTime = sellTrans.time;
                    }

                    // Determine which order(s) to place based on which transaction occurred more recently
                    var ordersToAdd = new List<(string instruction, decimal price, string reason)>();

                    if (sellTransTime.HasValue && (!buyTransTime.HasValue || sellTransTime > buyTransTime))
                    {
                        // Sell occurred more recently (or no buy found) -> place a BUY order
                        ordersToAdd.Add(("BUY_TO_COVER", buyPrice, $"Sell at ${sellPrice} occurred at {sellTransTime:yyyy-MM-dd HH:mm:ss}, need to buy back"));
                    }
                    else if (buyTransTime.HasValue && (!sellTransTime.HasValue || buyTransTime > sellTransTime))
                    {
                        // Buy occurred more recently (or no sell found) -> place a SELL order
                        ordersToAdd.Add(("SELL_SHORT", sellPrice, $"Buy at ${buyPrice} occurred at {buyTransTime:yyyy-MM-dd HH:mm:ss}, need to sell"));
                    }
                    else
                    {
                        // No transactions found for this pair - show both potential orders
                        ordersToAdd.Add(("BUY_TO_COVER", buyPrice, "No recent transactions - potential buy order"));
                        ordersToAdd.Add(("SELL_SHORT", sellPrice, "No recent transactions - potential sell order"));
                    }

                    // Add each order if it doesn't already exist in open orders
                    foreach (var (instruction, orderPrice, reason) in ordersToAdd)
                    {
                        bool orderExists = openOrders.Any(o =>
                            Math.Abs(o.price - orderPrice) <= 0.10m &&
                            (o.instruction == instruction ||
                             (instruction == "BUY_TO_COVER" && o.instruction == "BUY") ||
                             (instruction == "SELL_SHORT" && o.instruction == "SELL")));

                        if (!orderExists)
                        {
                            pendingOrders.Add(new
                            {
                                symbol = SYMBOL,
                                quantity = QUANTITY,
                                price = orderPrice,
                                instruction = instruction,
                                pairBuyPrice = buyPrice,
                                pairSellPrice = sellPrice,
                                reason = reason,
                                lastBuyTransactionTime = buyTransTime?.ToString("yyyy-MM-dd HH:mm:ss"),
                                lastSellTransactionTime = sellTransTime?.ToString("yyyy-MM-dd HH:mm:ss")
                            });
                        }
                    }
                }

                var result = new
                {
                    symbol = SYMBOL,
                    quantity = QUANTITY,
                    pricePairs = pricePairs.Select(p => new { buyPrice = p.buyPrice, sellPrice = p.sellPrice }),
                    pendingOrders = pendingOrders,
                    openOrderCount = openOrders.Count,
                    transactionCount = recentTransactions.Count
                };

                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        public async Task<IActionResult> TradeDash()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        public async Task<IActionResult> GridTradeDashboard()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        public async Task<IActionResult> PositionsDashboard()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        public async Task<IActionResult> FillOrKill()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        public async Task<IActionResult> BuyMstr()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        public async Task<IActionResult> SellMstr()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens != null)
                {
                    // Check if token is expired and refresh if needed
                    if (storedTokens.IsExpired)
                    {
                        try
                        {
                            var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                            // Store refreshed tokens
                            HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                            HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                            HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                            _tokenStorage.SaveTokens(refreshedTokens);
                            accessToken = refreshedTokens.AccessToken;
                        }
                        catch
                        {
                            // Refresh failed, redirect to login
                            return RedirectToAction("Login");
                        }
                    }
                    else
                    {
                        // Token is still valid, use it
                        HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                        accessToken = storedTokens.AccessToken;
                    }
                }
                else
                {
                    return RedirectToAction("Login");
                }
            }

            ViewBag.HasToken = !string.IsNullOrEmpty(accessToken);
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> PlaceOrder([FromBody] MyApi.Models.OrderRequest orderRequest, string password = "")
        {
            // Check password
            if (!CheckPassword(password, "PlaceOrder"))
            {
                return Unauthorized("Invalid password");
            }

            var accessToken = await GetValidAccessTokenAsync();
            var accountHash = Request.Query["accountHash"].ToString();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            var result = await _orderService.PlaceOrderAsync(orderRequest, accessToken ?? "", accountHash);

            if (result.Success)
            {
                return Ok(new { success = true, message = result.Message, data = result.Data });
            }
            else
            {
                return StatusCode(result.StatusCode, new { success = false, message = result.Message });
            }
        }

        private bool CheckPassword(string providedPassword, string endpoint)
        {
            var savedPassword = _configuration["Schwab:ApiPassword"];

            // If no password is set in configuration, allow access
            if (string.IsNullOrEmpty(savedPassword))
            {
                return true;
            }

            // Check if the provided password matches
            if (providedPassword == savedPassword)
            {
                return true;
            }

            // Log failed attempt
            //LogFailedPasswordAttempt(providedPassword, endpoint);
            return false;
        }

        private void LogFailedPasswordAttempt(string attemptedPassword, string endpoint)
        {
            var failedAttemptsJson = HttpContext.Session.GetString("failed_attempts");
            var failedAttempts = new List<string>();

            if (!string.IsNullOrEmpty(failedAttemptsJson))
            {
                try
                {
                    failedAttempts = JsonSerializer.Deserialize<List<string>>(failedAttemptsJson) ?? new List<string>();
                }
                catch { }
            }

            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            var attemptMessage = $"[{timestamp}] Endpoint: {endpoint} - Attempted password: '{attemptedPassword}'";
            failedAttempts.Add(attemptMessage);

            // Keep only the last 50 attempts to avoid session bloat
            if (failedAttempts.Count > 50)
            {
                failedAttempts = failedAttempts.Skip(failedAttempts.Count - 50).ToList();
            }

            HttpContext.Session.SetString("failed_attempts", JsonSerializer.Serialize(failedAttempts));
        }

        private async Task<TokenResponse> ExchangeCodeForTokenAsync(string code)
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

        private async Task<TokenResponse> RefreshAccessTokenAsync(string refreshToken)
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

        /// <summary>
        /// Gets a valid access token, automatically refreshing if expired or about to expire.
        /// Returns null if no token is available and refresh fails.
        /// </summary>
        private async Task<string?> GetValidAccessTokenAsync()
        {
            var accessToken = HttpContext.Session.GetString("access_token");

            // If no token in session, try to load from file
            if (string.IsNullOrEmpty(accessToken))
            {
                var storedTokens = _tokenStorage.LoadTokens();
                if (storedTokens == null)
                {
                    return null;
                }

                // Check if token is expired and refresh if needed
                if (storedTokens.IsExpired)
                {
                    try
                    {
                        var refreshedTokens = await RefreshAccessTokenAsync(storedTokens.RefreshToken);

                        // Store refreshed tokens
                        HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                        HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                        HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                        _tokenStorage.SaveTokens(refreshedTokens);
                        return refreshedTokens.AccessToken;
                    }
                    catch
                    {
                        return null;
                    }
                }
                else
                {
                    // Token is still valid, use it
                    HttpContext.Session.SetString("access_token", storedTokens.AccessToken);
                    HttpContext.Session.SetString("refresh_token", storedTokens.RefreshToken);
                    HttpContext.Session.SetInt32("expires_in", storedTokens.ExpiresIn);
                    return storedTokens.AccessToken;
                }
            }

            // Token exists in session, but check if file version is expired and needs refresh
            var fileTokens = _tokenStorage.LoadTokens();
            if (fileTokens != null && fileTokens.IsExpired)
            {
                try
                {
                    var refreshedTokens = await RefreshAccessTokenAsync(fileTokens.RefreshToken);

                    // Store refreshed tokens
                    HttpContext.Session.SetString("access_token", refreshedTokens.AccessToken);
                    HttpContext.Session.SetString("refresh_token", refreshedTokens.RefreshToken);
                    HttpContext.Session.SetInt32("expires_in", refreshedTokens.ExpiresIn);

                    _tokenStorage.SaveTokens(refreshedTokens);
                    return refreshedTokens.AccessToken;
                }
                catch
                {
                    // Refresh failed, return existing session token (may still work)
                    return accessToken;
                }
            }

            return accessToken;
        }

        // Proxy endpoint for Schwab stock quotes
        [HttpGet]
        public async Task<IActionResult> GetSchwabQuote(string symbol, string password = "")
        {
            // Check password
            if (!CheckPassword(password, "GetSchwabQuote"))
            {
                return Unauthorized("Invalid password");
            }

            if (string.IsNullOrEmpty(symbol))
            {
                return BadRequest("Symbol is required");
            }

            var accessToken = await GetValidAccessTokenAsync();

            if (string.IsNullOrEmpty(accessToken))
            {
                return Unauthorized("Not authenticated with Schwab");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Schwab Market Data API endpoint
                var apiUrl = $"https://api.schwabapi.com/marketdata/v1/quotes?symbols={Uri.EscapeDataString(symbol)}&fields=quote";
                var response = await client.GetAsync(apiUrl);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    return Content(content, "application/json");
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    return StatusCode((int)response.StatusCode, errorContent);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        // Proxy endpoint for EODHD stock quotes to avoid CORS issues
        [HttpGet]
        public async Task<IActionResult> GetStockQuote(string symbol)
        {
            if (string.IsNullOrEmpty(symbol))
            {
                return BadRequest("Symbol is required");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var apiToken = _configuration["EODHD:ApiToken"];

                // If symbol already includes exchange suffix (e.g., "BTC.US"), use as-is
                // Otherwise append .US suffix
                var apiSymbol = symbol.Contains(".") ? symbol : $"{symbol}.US";

                var url = $"https://eodhistoricaldata.com/api/real-time/{Uri.EscapeDataString(apiSymbol)}?api_token={apiToken}&fmt=json";

                var response = await client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    return Content(content, "application/json");
                }
                else
                {
                    return StatusCode((int)response.StatusCode, content);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }

        // Proxy endpoint for EODHD historical stock data to avoid CORS issues
        [HttpGet]
        public async Task<IActionResult> GetStockHistory(string symbol, string from, string to)
        {
            if (string.IsNullOrEmpty(symbol))
            {
                return BadRequest("Symbol is required");
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var apiToken = _configuration["EODHD:ApiToken"];
                var url = $"https://eodhistoricaldata.com/api/eod/{Uri.EscapeDataString(symbol)}.US?api_token={apiToken}&fmt=json";

                if (!string.IsNullOrEmpty(from))
                {
                    url += $"&from={Uri.EscapeDataString(from)}";
                }

                if (!string.IsNullOrEmpty(to))
                {
                    url += $"&to={Uri.EscapeDataString(to)}";
                }

                var response = await client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    return Content(content, "application/json");
                }
                else
                {
                    return StatusCode((int)response.StatusCode, content);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error: {ex.Message}");
            }
        }
    }
}
