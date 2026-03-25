using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.StackExchangeRedis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PrjAuth.Application.Configuration;
using PrjAuth.Application.Contracts.Implements;
using PrjAuth.Application.Contracts.Interfaces;
using System.Text;
using System.Threading.Tasks;
using System;

namespace PrjAuth.Api.ServiceExtensions
{
	public static class LoadBalancingExtensions
	{
		public static IServiceCollection AddLoadBalancedTokenConfiguration(this IServiceCollection services, IConfiguration configuration)
		{
			// Opcional: habilitar Redis se configurado
			var redisSection = configuration.GetSection("Redis");
			var useRedis = bool.TryParse(configuration["Jwt:UseRedis"], out var u) ? u : redisSection.Exists();

			if (useRedis)
			{
				services.AddStackExchangeRedisCache(options =>
				{
					options.Configuration = configuration["Redis:Connection"] ?? configuration["ConnectionStrings:Redis"] ?? "localhost:6379";
					options.InstanceName = configuration["Redis:InstanceName"] ?? "JwtAuth";
				});
			}
			else
			{
				// Garante que exista uma implementação de IDistributedCache mesmo quando não houver Redis
				services.AddDistributedMemoryCache();
			}

			// Registra configuração (pode depender do IDistributedCache)
			services.AddSingleton<LoadBalancedTokenConfiguration>(provider =>
			{
				var cache = provider.GetRequiredService<IDistributedCache>();
				var logger = provider.GetRequiredService<ILogger<LoadBalancedTokenConfiguration>>();
				return new LoadBalancedTokenConfiguration(configuration, cache, logger);
			});

			// Lista negra distribuída (sua implementação já usa IDistributedCache)
			services.AddScoped<ITokenBlackListService, TokenBlackListService>();
			// registrar validator
			services.AddScoped<ITokenValidator, SecurityHardenedTokenValidator>();
			return services;
		}

		public static IServiceCollection AddLoadBalancedJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
		{
			var section = configuration.GetSection("JwtSettings");
			if (!section.Exists()) section = configuration.GetSection("Jwt");
			var primary = section["PrimaryKey"] ?? section["Key"] ?? string.Empty;
			var secondary = section["SecondaryKey"] ?? string.Empty;
			var issuer = section["Issuer"] ?? string.Empty;
			var audience = section["Audience"] ?? string.Empty;

			// Use um único AuthenticationBuilder e defina o esquema padrão como "primary"
			var authBuilder = services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = "primary";
				options.DefaultChallengeScheme = "primary";
			});

			authBuilder.AddJwtBearer("primary", options =>
			{
				options.RequireHttpsMetadata = true;
				options.SaveToken = true;
				options.TokenValidationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(primary)),
					ValidateIssuer = true,
					ValidIssuer = issuer,
					ValidateAudience = true,
					ValidAudience = audience,
					ValidateLifetime = true,
					ClockSkew = System.TimeSpan.FromMinutes(1)
				};

				// Rejeita tokens cuja jti esteja na blacklist
				options.Events = new JwtBearerEvents
				{
					OnTokenValidated = async context =>
					{
						try
						{
							var jti = context.Principal?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti)?.Value;
							if (!string.IsNullOrEmpty(jti))
							{
								var blackList = context.HttpContext.RequestServices.GetService(typeof(ITokenBlackListService)) as ITokenBlackListService;
								if (blackList != null)
								{
									var isBlacklisted = await blackList.IsTokenBlacklistedAsync(jti).ConfigureAwait(false);
									if (isBlacklisted)
									{
										// marca falha para que o middleware retorne 401
										context.Fail("Token is blacklisted.");
										return;
									}
								}
							}
						}
						catch (Exception ex)
						{
							var loggerFactory = context.HttpContext.RequestServices.GetService(typeof(ILoggerFactory)) as ILoggerFactory;
							loggerFactory?.CreateLogger("JwtBearer").LogWarning(ex, "Erro ao verificar blacklist no OnTokenValidated");
							context.Fail("Token validation failed.");
						}
					}
				};
			});

			if (!string.IsNullOrWhiteSpace(secondary))
			{
				// registra secondary no mesmo builder e aplica a mesma checagem de blacklist
				authBuilder.AddJwtBearer("secondary", options =>
				{
					options.RequireHttpsMetadata = true;
					options.SaveToken = true;
					options.TokenValidationParameters = new TokenValidationParameters
					{
						ValidateIssuerSigningKey = true,
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secondary)),
						ValidateIssuer = true,
						ValidIssuer = issuer,
						ValidateAudience = true,
						ValidAudience = audience,
						ValidateLifetime = true,
						ClockSkew = System.TimeSpan.FromMinutes(1)
					};

					options.Events = new JwtBearerEvents
					{
						OnTokenValidated = async context =>
						{
							try
							{
								var jti = context.Principal?.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti)?.Value;
								if (!string.IsNullOrEmpty(jti))
								{
									var blackList = context.HttpContext.RequestServices.GetService(typeof(ITokenBlackListService)) as ITokenBlackListService;
									if (blackList != null)
									{
										var isBlacklisted = await blackList.IsTokenBlacklistedAsync(jti).ConfigureAwait(false);
										if (isBlacklisted)
										{
											context.Fail("Token is blacklisted.");
											return;
										}
									}
								}
							}
							catch (Exception ex)
							{
								var loggerFactory = context.HttpContext.RequestServices.GetService(typeof(ILoggerFactory)) as ILoggerFactory;
								loggerFactory?.CreateLogger("JwtBearer").LogWarning(ex, "Erro ao verificar blacklist no OnTokenValidated (secondary)");
								context.Fail("Token validation failed.");
							}
						}
					};
				});
			}

			services.AddAuthorization(options =>
			{
				options.AddPolicy("JwtMultiple", policy =>
				{
					policy.AddAuthenticationSchemes("primary", "secondary");
					policy.RequireAuthenticatedUser();
				});
			});

			return services;
		}
	}
}
