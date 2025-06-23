using Confluent.Kafka;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace FraudService
{
    public class Transaction
    {
        public Guid Id { get; set; }
        public decimal Amount { get; set; }
        public string UserId { get; set; }
        public DateTime Timestamp { get; set; }
        public string Status { get; set; }
    }

    public class FraudDetectionService : BackgroundService
    {
        private readonly IConsumer<Null, string> _consumer;
        private readonly AppDbContext _context;
        private readonly ILogger<FraudDetectionService> _logger;

        public FraudDetectionService(AppDbContext context, ILogger<FraudDetectionService> logger)
        {
            _context = context;
            _logger = logger;
            var config = new ConsumerConfig
            {
                GroupId = "fraud-group",
                BootstrapServers = "localhost:9092",
                AutoOffsetReset = AutoOffsetReset.Earliest
            };
            _consumer = new ConsumerBuilder<Null, string>(config).Build();
            _consumer.Subscribe("transactions");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var result = _consumer.Consume(stoppingToken);
                var transaction = JsonSerializer.Deserialize<Transaction>(result.Message.Value);

                if (IsFraudulent(transaction))
                {
                    _logger.LogWarning($"Fraud detected: Transaction {transaction.Id}, Amount: {transaction.Amount}");
                    transaction.Status = "Flagged";
                    await UpdateTransactionStatus(transaction);
                }
            }
        }

        private bool IsFraudulent(Transaction transaction)
        {
            // Simple rule: Flag transactions over $10,000
            return transaction.Amount > 10000;
        }

        private async Task UpdateTransactionStatus(Transaction transaction)
        {
            var existing = await _context.Transactions.FindAsync(transaction.Id);
            if (existing != null)
            {
                existing.Status = transaction.Status;
                await _context.SaveChangesAsync();
            }
        }
    }

    public class AppDbContext : DbContext
    {
        public DbSet<Transaction> Transactions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Transaction>().ToTable("transactions");
        }
    }
}