using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using AuthorizationServer.Models;

namespace AuthorizationServer.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }

        public DbSet<Client> Clients { get; set; }
        public DbSet<AuthorizationCode> AuthorizationCodes { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Seed default client
            var client = new Client
            {
                Id = 1,
                ClientId = "test-client",
                ClientSecret = "test-secret",
                ClientName = "Test Client",
                RedirectUri = "https://localhost:5003/auth/callback",
                Scope = "read write",
                IsActive = true
            };
            
            builder.Entity<Client>().HasData(client);
            
            // Log the client being seeded
            Console.WriteLine($"[DEBUG] Seeding client: {System.Text.Json.JsonSerializer.Serialize(client)}");
        }
    }
}