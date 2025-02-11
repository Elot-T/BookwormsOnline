using BookwormsOnline;
using Microsoft.EntityFrameworkCore;

public class SessionValidationMiddleware
{
    private readonly RequestDelegate _next;

    public SessionValidationMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, MyDbContext dbContext)
    {
        var sessionToken = context.Request.Cookies["SessionToken"];

        if (!string.IsNullOrEmpty(sessionToken))
        {
            var session = await dbContext.UserSessions
                .FirstOrDefaultAsync(s =>
                    s.SessionId == sessionToken &&
                    s.IsActive &&
                    s.SessionExpiryTime > DateTime.UtcNow);

            if (session == null)
            {
                // Clear invalid session
                context.Response.Cookies.Delete("SessionToken");
                context.Session.Clear();
                context.Response.Redirect("/Users/Login");
                return;
            }

            // Update last activity
            session.LastActivityTime = DateTime.UtcNow;
            await dbContext.SaveChangesAsync();

            // Store session in context
            context.Items["CurrentSession"] = session;
        }

        await _next(context);
    }
}