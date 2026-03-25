using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PrjAuth.Domain.Interfaces;
using PrjAuth.Infra.DataContexts;
using PrjAuth.Infra.Repositories;

namespace PrjAuth.Infra.ServiceExtensions
{
	public static class InfraExtension
	{
		public static IServiceCollection AddDIInfrastuctureServices(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddDbContext<DbAuthContext>(options =>
			{
				options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
			});

			services.AddScoped<IUnitOfWork, UnitOfWork>();
			services.AddScoped<IUserRepository, UserRepository>();
			services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
			services.AddScoped<ISecurityEventRepository, SecurityEventRepository>();
			return services;
		}
	}
}
