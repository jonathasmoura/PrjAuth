using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Implements;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Configuration;

namespace PrjAuth.Application.ServiceExtensions
{
	public static class ApplicationExtension
	{
		public static IServiceCollection AddDIApplicationServices(this IServiceCollection services, IConfiguration configuration)
		{

			services.AddMemoryCache();


			var redisConfig = configuration.GetConnectionString("Redis") ?? configuration["Redis:Configuration"];
			if (!string.IsNullOrWhiteSpace(redisConfig))
			{
				services.AddStackExchangeRedisCache(opts =>
				{
					opts.Configuration = redisConfig;
				});
			}
			else
			{
				services.AddDistributedMemoryCache();
			}


			services.AddSingleton<LoadBalancedTokenConfiguration>(sp =>
			{
				var cfg = sp.GetRequiredService<IConfiguration>();
				var cache = sp.GetRequiredService<Microsoft.Extensions.Caching.Distributed.IDistributedCache>();
				var logger = sp.GetRequiredService<ILogger<LoadBalancedTokenConfiguration>>();
				return new LoadBalancedTokenConfiguration(cfg, cache, logger);
			});

			services.AddScoped<IUserService, UserService>();
			services.AddScoped<ITokenService, TokenService>();
			services.AddScoped<IRefreshTokenService, RefreshTokenService>();
			services.AddScoped<IAlertingService, AlertingService>();
			services.AddScoped<IAuthService, AuthService>();

			services.AddScoped<ITokenBlackListService, TokenBlackListService>();
			services.AddScoped<ITokenValidator, SecurityHardenedTokenValidator>();
			services.AddScoped<IOptimizedUserService, OptimizedUserService>();
			services.AddScoped<ISecurityMonitoringService, SecurityMonitoringService>();
			services.AddScoped<IClientIpExtractor, ClientIpExtractor>();
			services.AddScoped<ITokenBlacklistHelper, TokenBlacklistHelper>();

			services.AddHttpContextAccessor();

			return services;
		}
	}
}
