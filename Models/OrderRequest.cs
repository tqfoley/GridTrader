namespace MyApi.Models
{
    public class OrderRequest
    {
        public string? Symbol { get; set; }
        public int Quantity { get; set; }
        public string OrderType { get; set; } = "MARKET"; // MARKET or LIMIT
        public decimal? Price { get; set; } // Required for LIMIT orders
        public string Instruction { get; set; } = "BUY"; // BUY, SELL, SELL_SHORT, or BUY_TO_COVER
        public string Duration { get; set; } = "DAY"; // DAY, GTC, etc.
        public string Session { get; set; } = "NORMAL"; // NORMAL, SEAMLESS (extended hours)
        public string? CancelDate { get; set; } // Optional cancel date for GTC orders (yyyy-MM-dd format)
    }
}
