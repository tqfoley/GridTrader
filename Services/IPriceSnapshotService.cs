using SchwabOAuthApp.Models;

namespace SchwabOAuthApp.Services
{
    public interface IPriceSnapshotService
    {
        /// <summary>Creates the price_snapshots table if it does not exist yet.</summary>
        Task EnsureTableAsync();

        /// <summary>Pings Neon and returns connection details plus the current row count.</summary>
        Task<NeonStatus> GetStatusAsync();

        /// <summary>Inserts a new row and returns it (with the generated id and timestamp).</summary>
        Task<PriceSnapshot> SaveAsync(string ticker, decimal priceUsd, string service);

        /// <summary>Returns the most recent rows, newest first.</summary>
        Task<List<PriceSnapshot>> GetRecentAsync(int limit = 50);
    }
}
