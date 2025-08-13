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
            builder.Entity<Client>().HasData(new Client
            {
                Id = 1,
                ClientId = "test-client",
                ClientSecret = "test-secret",
                ClientName = "Test Client",
                RedirectUri = "https://localhost:5003/callback",
                Scope = "read write",
                IsActive = true
            });
        }
    }
}