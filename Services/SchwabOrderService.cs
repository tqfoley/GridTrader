using System.Text;
using System.Text.Json;
using MyApi.Models;

namespace MyApi.Services
{
    public class SchwabOrderResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string? Data { get; set; }
        public int StatusCode { get; set; }
    }

    public class SchwabOrderService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private const string ApiBaseUrl = "https://api.schwabapi.com/trader/v1";

        public SchwabOrderService(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task<SchwabOrderResult> PlaceOrderAsync(OrderRequest orderRequest, string accessToken, string accountHash)
        {
            if (string.IsNullOrEmpty(orderRequest.Symbol) || orderRequest.Quantity <= 0)
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = "Symbol and quantity are required",
                    StatusCode = 400
                };
            }

            if (string.IsNullOrEmpty(accountHash))
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = "Account hash is required",
                    StatusCode = 400
                };
            }

            if (string.IsNullOrEmpty(accessToken))
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = "Not authenticated with Schwab",
                    StatusCode = 401
                };
            }

            // Validate special trade restrictions
            var restrictionResult = ValidateTradeRestrictions(orderRequest);
            if (!restrictionResult.Success)
            {
                return restrictionResult;
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
                client.DefaultRequestHeaders.Add("Accept", "application/json");

                // Build the order payload
                var orderPayload = BuildOrderPayload(orderRequest);
                var jsonContent = JsonSerializer.Serialize(orderPayload);
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var apiUrl = $"{ApiBaseUrl}/accounts/{accountHash}/orders";
                var response = await client.PostAsync(apiUrl, content);

                var responseContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    // Log the order to file
                    await LogOrderAsync(orderRequest, jsonContent, responseContent, true);

                    return new SchwabOrderResult
                    {
                        Success = true,
                        Message = "Order placed successfully",
                        Data = responseContent,
                        StatusCode = (int)response.StatusCode
                    };
                }
                else
                {
                    // Log failed order attempt
                    await LogOrderAsync(orderRequest, jsonContent, responseContent, false);

                    return new SchwabOrderResult
                    {
                        Success = false,
                        Message = responseContent,
                        StatusCode = (int)response.StatusCode
                    };
                }
            }
            catch (Exception ex)
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = $"Error: {ex.Message}",
                    StatusCode = 500
                };
            }
        }

        private object BuildOrderPayload(OrderRequest orderRequest)
        {
            // Determine positionEffect for short selling
            string? positionEffect = null;
            if (orderRequest.Instruction == "SELL_SHORT")
            {
                positionEffect = "OPENING";
            }
            else if (orderRequest.Instruction == "BUY_TO_COVER")
            {
                positionEffect = "CLOSING";
            }

            // Build order leg based on whether positionEffect is needed
            object orderLeg;
            if (positionEffect != null)
            {
                orderLeg = new
                {
                    instruction = orderRequest.Instruction,
                    quantity = orderRequest.Quantity,
                    positionEffect = positionEffect,
                    instrument = new
                    {
                        symbol = orderRequest.Symbol,
                        assetType = "EQUITY"
                    }
                };
            }
            else
            {
                orderLeg = new
                {
                    instruction = orderRequest.Instruction,
                    quantity = orderRequest.Quantity,
                    instrument = new
                    {
                        symbol = orderRequest.Symbol,
                        assetType = "EQUITY"
                    }
                };
            }

            // Build the order payload (cancelTime is not used)
            var orderPayload = new
            {
                orderType = orderRequest.OrderType,
                session = orderRequest.Session,
                duration = orderRequest.Duration,
                orderStrategyType = "SINGLE",
                orderLegCollection = new[] { orderLeg },
                price = orderRequest.Price
            };

            return orderPayload;
        }

        private async Task LogOrderAsync(OrderRequest orderRequest, string requestPayload, string responseContent, bool success)
        {
            try
            {
                var ordersFolder = Path.Combine(Directory.GetCurrentDirectory(), "orders");
                if (!Directory.Exists(ordersFolder))
                {
                    Directory.CreateDirectory(ordersFolder);
                }

                var timestamp = DateTime.Now.ToString("yyyy-MM-dd_HH-mm-ss");
                var status = success ? "" : "_FAILED";
                var fileName = $"{orderRequest.Symbol}_{timestamp}{status}.txt";
                var filePath = Path.Combine(ordersFolder, fileName);

                var orderLog = $"Order {(success ? "Placed" : "FAILED")}: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
                              $"Symbol: {orderRequest.Symbol}\n" +
                              $"Instruction: {orderRequest.Instruction}\n" +
                              $"Quantity: {orderRequest.Quantity}\n" +
                              $"Order Type: {orderRequest.OrderType}\n" +
                              $"Price: {orderRequest.Price}\n" +
                              $"Duration: {orderRequest.Duration}\n" +
                              $"Session: {orderRequest.Session}\n" +
                              $"Cancel Date: {orderRequest.CancelDate ?? "N/A"}\n" +
                              $"\nRequest Payload:\n{requestPayload}\n" +
                              $"\nAPI Response:\n{responseContent}";

                await File.WriteAllTextAsync(filePath, orderLog);
            }
            catch (Exception ex)
            {
                // Log file save error but don't fail the order
                Console.WriteLine($"Failed to save order log: {ex.Message}");
            }
        }

        /// <summary>
        /// Validates trade restrictions before placing an order.
        /// Returns a failed result if any restriction is violated.
        /// </summary>
        private SchwabOrderResult ValidateTradeRestrictions(OrderRequest orderRequest)
        {
            var symbol = orderRequest.Symbol?.ToUpper() ?? "";
            var quantity = orderRequest.Quantity;
            var instruction = orderRequest.Instruction?.ToUpper() ?? "";

            // Restriction 1: No orders of 26 to 39 share amounts (buy or sell)
            if (quantity >= 26 && quantity <= 39)
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = $"Trade restriction: Orders of 26 to 39 shares are not allowed. Quantity: {quantity}",
                    StatusCode = 400
                };
            }

            // Restriction 2: QBTS orders must be exactly 10 shares
            if (symbol == "QBTS" && quantity != 10)
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = $"Trade restriction: QBTS orders must be exactly 10 shares. Quantity: {quantity}",
                    StatusCode = 400
                };
            }

            // Restriction 3: QBTS should only allow SELL_SHORT or BUY_TO_COVER
            if (symbol == "QBTS" && instruction != "SELL_SHORT" && instruction != "BUY_TO_COVER")
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = $"Trade restriction: QBTS orders only allow SELL_SHORT or BUY_TO_COVER. Instruction: {instruction}",
                    StatusCode = 400
                };
            }

            // Restriction 4: TSLA trades must be multiples of 5 for share count
            if (symbol == "TSLA" && quantity % 5 != 0)
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = $"Trade restriction: TSLA orders must be in multiples of 5 shares. Quantity: {quantity}",
                    StatusCode = 400
                };
            }

            // Restriction 5: Only FBTC, IBIT, and TSLA can be market orders
            var marketOrderAllowed = new[] { "FBTC", "IBIT", "TSLA" };
            var orderType = orderRequest.OrderType?.ToUpper() ?? "";
            if (orderType == "MARKET" && !marketOrderAllowed.Contains(symbol))
            {
                return new SchwabOrderResult
                {
                    Success = false,
                    Message = $"Trade restriction: Market orders are only allowed for FBTC, IBIT, and TSLA. Symbol: {symbol}",
                    StatusCode = 400
                };
            }

            // All restrictions passed
            return new SchwabOrderResult { Success = true };
        }
    }
}
