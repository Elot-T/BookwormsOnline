using Microsoft.EntityFrameworkCore;
using BookwormsOnline.Models;
using BookwormsOnline;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Identity.UI.Services;
using BookwormsOnline.Services; // Add this namespace

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddHostedService<SessionCleanupService>();


builder.Services.AddAuthentication(options =>
{
    options.DefaultForbidScheme = "ForbiddenScheme";
})
.AddCookie("ForbiddenScheme", options =>
{
    options.AccessDeniedPath = "/Error/403";
});

// Rest of your existing services configuration...
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});


// Session configuration
builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Register DbContext with MySQL provider
builder.Services.AddDbContext<MyDbContext>(options =>
    options.UseMySQL(builder.Configuration.GetConnectionString("DefaultConnection"))
           .EnableSensitiveDataLogging()
           .LogTo(Console.WriteLine, LogLevel.Information));

// Register EmailSender as IEmailSender
builder.Services.AddSingleton<IEmailSender, EmailSender>();

// Optional: Swagger setup
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();



// Add logging
builder.Services.AddLogging(config =>
{
    config.AddConsole();
    config.AddDebug();
    config.SetMinimumLevel(LogLevel.Information);
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseExceptionHandler("/Error/500");
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/Error/{0}");

// Add authentication middleware
app.UseAuthentication();  // This must come before UseAuthorization()
app.UseAuthorization();

// Rest of your middleware configuration...
app.UseStaticFiles();
app.UseSession();
app.UseHttpsRedirection();
app.UseRouting();
app.UseMiddleware<SessionValidationMiddleware>();

// Existing routes
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapFallbackToController("NotFound", "Error");

app.Run();