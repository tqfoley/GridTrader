namespace SchwabOAuthApp.Models
{
    /// <summary>
    /// One saved price observation stored in the Neon (Postgres) price_snapshots table.
    /// </summary>
    public class PriceSnapshot
    {
        public Guid Id { get; set; }
        public string Ticker { get; set; } = string.Empty;
        public decimal PriceUsd { get; set; }
        public string Service { get; set; } = string.Empty;
        public DateTimeOffset RecordedAt { get; set; }
    }

    /// <summary>
    /// Result of a Neon connectivity check shown on the Price Log page.
    /// </summary>
    public class NeonStatus
    {
        public bool Connected { get; set; }
        public string? ServerVersion { get; set; }
        public string? Database { get; set; }
        public long RowCount { get; set; }
        public long LatencyMs { get; set; }
        public string? Error { get; set; }
    }
}
