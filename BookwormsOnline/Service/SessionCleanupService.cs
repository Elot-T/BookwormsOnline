using BookwormsOnline;
using Microsoft.EntityFrameworkCore;

public class SessionCleanupService : BackgroundService
{
    private readonly IServiceProvider _services;

    public SessionCleanupService(IServiceProvider services)
    {
        _services = services;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            using var scope = _services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<MyDbContext>();

            var expiredSessions = await dbContext.UserSessions
                .Where(s => s.SessionExpiryTime < DateTime.UtcNow)
                .ToListAsync();

            foreach (var session in expiredSessions)
            {
                session.IsActive = false;
            }

            await dbContext.SaveChangesAsync();
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); // Run every 5 minutes
        }
    }
}