using BookwormsOnline.Models;
using System.ComponentModel.DataAnnotations;

public class UserSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string SessionId { get; set; } = Guid.NewGuid().ToString();
    public string DeviceInfo { get; set; }
    public string IpAddress { get; set; }
    public DateTime LoginTime { get; set; } = DateTime.UtcNow;
    public DateTime LastActivityTime { get; set; } = DateTime.UtcNow;
    public DateTime SessionExpiryTime { get; set; }
    public bool IsActive { get; set; } = true;

    // Remove TokenHash property
    [ConcurrencyCheck]
    public Guid ConcurrencyToken { get; set; } = Guid.NewGuid();

    public User User { get; set; }
}