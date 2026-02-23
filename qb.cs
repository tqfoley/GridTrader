// Program.cs
using Microsoft.AspNetCore.Authentication.Cookies;
using SchwabOAuthApp;
using SchwabOAuthApp.Models;

namespace SchwabOAuthApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container
            builder.Services.AddControllersWithViews(options =>
            {
                options.Filters.Add<SchwabOAuthApp.Filters.TotpAuthorizationFilter>();
            });
            builder.Services.AddHttpClient();
            builder.Services.AddSingleton<SchwabOAuthApp.Services.ITotpService, SchwabOAuthApp.Services.TotpService>();
            builder.Services.AddSingleton<SchwabOAuthApp.Services.ITokenStorageService, SchwabOAuthApp.Services.TokenStorageService>();
            builder.Services.AddSingleton<SchwabOAuthApp.Services.IIpLoggerService, SchwabOAuthApp.Services.IpLoggerService>();
            builder.Services.AddScoped<MyApi.Services.SchwabOrderService>();
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromHours(12);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            });

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Schwab/Login";
                });

            var app = builder.Build();

            // Configure the HTTP request pipeline
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            // Add IP logging middleware (before other middleware to capture all requests)
            app.UseMiddleware<SchwabOAuthApp.Middleware.IpLoggingMiddleware>();

//            app.UseHttpsRedirection();
            app.UseStaticFiles();

            // Serve static files from Images folder
            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(
                    Path.Combine(Directory.GetCurrentDirectory(), "Images")),
                RequestPath = "/Images"
            });

            app.UseRouting();
            app.UseSession();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}

