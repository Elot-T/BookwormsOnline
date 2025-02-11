using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration; // Make sure this namespace is included
using BookwormsOnline.Models;

namespace BookwormsOnline
{
    public class MyDbContext : DbContext
    {
        public MyDbContext(DbContextOptions<MyDbContext> options)
            : base(options)
        { }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
                string connectionString = Environment.GetEnvironmentVariable("DefaultConnection")
                                          ?? throw new InvalidOperationException("Connection string is not set.");
                optionsBuilder.UseMySQL(connectionString);
            }
        }

        public DbSet<User> Users { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }
    }
}