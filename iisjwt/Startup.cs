// iisjwt/Startup.cs
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System;
using System.Threading.RateLimiting;

namespace WebApi
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            // ── Fail-fast config validation ───────────────────────────────────
            var jwt = Configuration.GetSection("JwtSettings").Get<JwtSettings>()
                      ?? new JwtSettings();

            if (jwt.TokenLifetimeMinutes is < 1 or > 1440)
                throw new InvalidOperationException(
                    "JwtSettings:TokenLifetimeMinutes must be between 1 and 1440.");

            if (string.IsNullOrWhiteSpace(jwt.ActiveSigningThumbprint) ||
                jwt.ActiveSigningThumbprint.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "JwtSettings:ActiveSigningThumbprint is not configured.");

            if (jwt.JwksCerts.Count == 0)
                throw new InvalidOperationException(
                    "JwtSettings:JwksCerts must contain at least one entry.");

            // Verify the signing cert and private key are accessible before serving traffic.
            try   { UserService.ValidateSigningCert(jwt.ActiveSigningThumbprint); }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"Cannot access signing cert at startup: {ex.Message}", ex);
            }

            // ── Services ──────────────────────────────────────────────────────
            services.AddCors();
            services.AddAuthentication(IISDefaults.AuthenticationScheme);
            services.AddControllers();
            services.Configure<JwtSettings>(Configuration.GetSection("JwtSettings"));
            services.AddScoped<IUserService, UserService>();

            // Per-IP rate limit on the token endpoint (20 req/min).
            services.AddRateLimiter(o =>
            {
                o.AddPolicy("token", ctx =>
                    RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            Window      = TimeSpan.FromMinutes(1),
                            PermitLimit = 20,
                            QueueLimit  = 0,
                        }));
                o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            });

            // Health check that re-validates the signing cert on each probe.
            services.AddHealthChecks()
                .AddCheck("jwt-signing-cert", () =>
                {
                    var cfg = Configuration.GetSection("JwtSettings").Get<JwtSettings>()
                              ?? new JwtSettings();
                    try
                    {
                        UserService.ValidateSigningCert(cfg.ActiveSigningThumbprint);
                        return HealthCheckResult.Healthy();
                    }
                    catch (Exception ex)
                    {
                        return HealthCheckResult.Unhealthy(ex.Message);
                    }
                });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseRouting();

            var origins = Configuration.GetSection("CorsOrigins").Get<string[]>()
                          ?? Array.Empty<string>();

            app.UseCors(x => x
                .WithOrigins(origins)
                .WithMethods("GET", "POST", "OPTIONS")
                .WithHeaders("Authorization", "Content-Type", "Accept")
                .AllowCredentials());

            app.UseRateLimiter();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(x =>
            {
                x.MapControllers();
                x.MapHealthChecks("/health");
            });
        }
    }
}
