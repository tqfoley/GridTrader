using System.Diagnostics;
using Npgsql;
using SchwabOAuthApp.Models;

namespace SchwabOAuthApp.Services
{
    /// <summary>
    /// Stores ticker price snapshots in a Neon Postgres database.
    /// Connection string comes from appsettings.json: "Neon": { "ConnectionString": "..." }.
    /// </summary>
    public class NeonPriceSnapshotService : IPriceSnapshotService, IDisposable
    {
        private const string TableName = "price_snapshots";

        private readonly NpgsqlDataSource? _dataSource;
        private readonly string? _configError;
        private readonly SemaphoreSlim _ensureLock = new(1, 1);
        private bool _tableEnsured;

        public NeonPriceSnapshotService(IConfiguration configuration)
        {
            var connectionString = configuration["Neon:ConnectionString"];
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                _configError = "Neon:ConnectionString is not set in appsettings.json";
                return;
            }

            try
            {
                _dataSource = NpgsqlDataSource.Create(connectionString);
            }
            catch (Exception ex)
            {
                _configError = $"Invalid Neon connection string: {ex.Message}";
            }
        }

        private NpgsqlDataSource DataSource =>
            _dataSource ?? throw new InvalidOperationException(_configError ?? "Neon is not configured");

        public async Task EnsureTableAsync()
        {
            if (_tableEnsured) return;

            await _ensureLock.WaitAsync();
            try
            {
                if (_tableEnsured) return;

                const string sql = $@"
                    CREATE TABLE IF NOT EXISTS {TableName} (
                        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        ticker      TEXT NOT NULL,
                        price_usd   NUMERIC(18, 6) NOT NULL,
                        service     TEXT NOT NULL,
                        recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    CREATE INDEX IF NOT EXISTS ix_{TableName}_recorded_at ON {TableName} (recorded_at DESC);";

                await using var cmd = DataSource.CreateCommand(sql);
                await cmd.ExecuteNonQueryAsync();
                _tableEnsured = true;
            }
            finally
            {
                _ensureLock.Release();
            }
        }

        public async Task<NeonStatus> GetStatusAsync()
        {
            var status = new NeonStatus();
            if (_dataSource == null)
            {
                status.Error = _configError;
                return status;
            }

            var sw = Stopwatch.StartNew();
            try
            {
                await EnsureTableAsync();

                await using var conn = await DataSource.OpenConnectionAsync();
                status.ServerVersion = conn.PostgreSqlVersion.ToString();
                status.Database = conn.Database;

                await using var cmd = new NpgsqlCommand($"SELECT COUNT(*) FROM {TableName}", conn);
                status.RowCount = (long)(await cmd.ExecuteScalarAsync() ?? 0L);
                status.Connected = true;
            }
            catch (Exception ex)
            {
                status.Error = ex.Message;
            }
            finally
            {
                sw.Stop();
                status.LatencyMs = sw.ElapsedMilliseconds;
            }

            return status;
        }

        public async Task<PriceSnapshot> SaveAsync(string ticker, decimal priceUsd, string service)
        {
            if (string.IsNullOrWhiteSpace(ticker)) throw new ArgumentException("Ticker is required", nameof(ticker));
            if (string.IsNullOrWhiteSpace(service)) throw new ArgumentException("Service is required", nameof(service));

            await EnsureTableAsync();

            const string sql = $@"
                INSERT INTO {TableName} (ticker, price_usd, service)
                VALUES (@ticker, @price, @service)
                RETURNING id, ticker, price_usd, service, recorded_at;";

            await using var cmd = DataSource.CreateCommand(sql);
            cmd.Parameters.AddWithValue("ticker", ticker.Trim().ToUpperInvariant());
            cmd.Parameters.AddWithValue("price", priceUsd);
            cmd.Parameters.AddWithValue("service", service.Trim());

            await using var reader = await cmd.ExecuteReaderAsync();
            await reader.ReadAsync();
            return Map(reader);
        }

        public async Task<List<PriceSnapshot>> GetRecentAsync(int limit = 50)
        {
            await EnsureTableAsync();

            const string sql = $@"
                SELECT id, ticker, price_usd, service, recorded_at
                FROM {TableName}
                ORDER BY recorded_at DESC, id DESC
                LIMIT @limit;";

            await using var cmd = DataSource.CreateCommand(sql);
            cmd.Parameters.AddWithValue("limit", Math.Clamp(limit, 1, 500));

            var rows = new List<PriceSnapshot>();
            await using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                rows.Add(Map(reader));
            }
            return rows;
        }

        private static PriceSnapshot Map(NpgsqlDataReader reader) => new()
        {
            Id = reader.GetGuid(0),
            Ticker = reader.GetString(1),
            PriceUsd = reader.GetDecimal(2),
            Service = reader.GetString(3),
            RecordedAt = reader.GetFieldValue<DateTime>(4).ToUniversalTime()
        };

        public void Dispose()
        {
            _dataSource?.Dispose();
            _ensureLock.Dispose();
        }
    }
}
