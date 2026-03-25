using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PrjAuth.Api.Middlewares;
using PrjAuth.Api.Config;

namespace PrjAuth.Api.ServiceExtensions
{
	public static class ApplicationBuilderExtensions
	{
		public static IApplicationBuilder UseAuthRateLimiting(this IApplicationBuilder app)
		{
			return app.UseMiddleware<AuthRateLimitingMiddleware>();
		}

		public static IServiceCollection AddAuthRateLimiting(this IServiceCollection services, IConfiguration configuration)
		{
			services.Configure<RateLimitingOptions>(configuration.GetSection("RateLimiting"));
			return services;
		}
	}
}
