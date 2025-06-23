using Confluent.Kafka;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace TransactionService.Controllers
{
    public class Transaction
    {
        public Guid Id { get; set; }
        public decimal Amount { get; set; }
        public string userID { get; set; }
        public DateTime timestamp { get; set; }
        public string Status { get; set; }
    }

    [ApiController]
    [Route("api/transactions")]
    public class TransactionController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IProducer<Null, string> _kafkaProducer;

        public TransactionController(AppDbContext context, IProducer<Null, string> kafkaProducer)
        {
            _context = context;
            _kafkaProducer = kafkaProducer;
        }

        [HttpPost]
        public async Task<IActionResult> CreateTransaction([FromBody] Transaction transaction)
        {
            transaction.Id = Guid.NewGuid();
            transaction.timestamp = DateTime.UtcNow;
            transaction.Status = "Pending";
            transaction.userID = User.FindFirst(ClaimTypes.Name)?.Value;

            _context.Transaction.Add(transaction);
            await _context.SaveChangesAsync();

            var message = new Message<Null, string> { Value = JsonSerializer.Serialize(transaction) };
            await _kafkaProducer.ProduceAsync("transactions", message);

            return Ok(new { TransactionId = transaction.Id });
        }
    }

    public class AppDbContext : DbContext
    {
        public DbSet<Transaction> Transactions { get; set; }
        public AppDbContext(AppDbContextOptions<AppDbContext>options) : base(options) {}
    }
}