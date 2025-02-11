using Microsoft.EntityFrameworkCore;
using BookwormsOnline.Models;
using BookwormsOnline;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews(); // For MVC and views

// Register DbContext with MySQL provider
builder.Services.AddDbContext<MyDbContext>(options =>
    options.UseMySQL(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register Swagger (Optional, for API documentation)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Enable serving of static files (like images)
app.UseStaticFiles();  // This is important for serving images

app.UseHttpsRedirection();

// Enable routing and controller mapping
app.UseRouting(); // Ensure that routing is enabled

app.UseAuthorization();

// Map controller routes for MVC views and actions
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// This will ensure the app starts correctly and handles all mapped routes
app.Run();
