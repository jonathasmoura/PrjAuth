using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PrjAuth.Application.Dtos;
using System;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.ServiceExtensions
{
	public static class AuthenticationExtension
	{
		public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration)
		{
			// Suporta ambas as seções (compatibilidade) e registra IOptions<JwtSettingsDto>
			var jwtSettings = new JwtSettingsDto();

			var sectionFull = configuration.GetSection("JwtSettings");
			var sectionShort = configuration.GetSection("Jwt");

			if (sectionFull.Exists())
			{
				sectionFull.Bind(jwtSettings);
				services.Configure<JwtSettingsDto>(sectionFull);
			}
			else if (sectionShort.Exists())
			{
				jwtSettings.SecretKey = sectionShort["Key"] ?? sectionShort["SecretKey"] ?? string.Empty;
				jwtSettings.Issuer = sectionShort["Issuer"] ?? string.Empty;
				jwtSettings.Audience = sectionShort["Audience"] ?? string.Empty;
				jwtSettings.AccessTokenExpirationMinutes = int.TryParse(sectionShort["AccessTokenExpirationMinutes"], out var m) ? m : jwtSettings.AccessTokenExpirationMinutes;
				jwtSettings.RefreshTokenExpirationDays = int.TryParse(sectionShort["RefreshTokenExpirationDays"], out var d) ? d : jwtSettings.RefreshTokenExpirationDays;

				services.Configure<JwtSettingsDto>(opts =>
				{
					opts.SecretKey = jwtSettings.SecretKey;
					opts.Issuer = jwtSettings.Issuer;
					opts.Audience = jwtSettings.Audience;
					opts.AccessTokenExpirationMinutes = jwtSettings.AccessTokenExpirationMinutes;
					opts.RefreshTokenExpirationDays = jwtSettings.RefreshTokenExpirationDays;
				});
			}
			else
			{
				throw new InvalidOperationException("Configuração JWT não encontrada. Configure 'JwtSettings' ou 'Jwt' no appsettings.");
			}

			// Validação explícita das opções para evitar start inválido
			if (string.IsNullOrWhiteSpace(jwtSettings.SecretKey) || jwtSettings.SecretKey.Length < 32)
			{
				throw new InvalidOperationException("Jwt secret key inválida. Configure um valor forte em 'Jwt:Key' ou 'JwtSettings:SecretKey' (mínimo 32 caracteres).");
			}
			if (string.IsNullOrWhiteSpace(jwtSettings.Issuer) || string.IsNullOrWhiteSpace(jwtSettings.Audience))
			{
				throw new InvalidOperationException("Jwt Issuer e Audience devem estar configurados.");
			}

			var keyBytes = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);

			services.AddAuthentication(options =>
			{
				options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
			})
			.AddJwtBearer(options =>
			{
				options.RequireHttpsMetadata = true;
				options.SaveToken = true;
				options.TokenValidationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
					ValidateIssuer = true,
					ValidIssuer = jwtSettings.Issuer,
					ValidateAudience = true,
					ValidAudience = jwtSettings.Audience,
					ValidateLifetime = true,
					ClockSkew = TimeSpan.FromMinutes(1)
				};

				options.Events = new JwtBearerEvents
				{
					OnAuthenticationFailed = context =>
					{
						var loggerFactory = context.HttpContext.RequestServices.GetService<ILoggerFactory>();
						var logger = loggerFactory?.CreateLogger("JwtBearer");
						logger?.LogWarning("JWT authentication failed: {Exception}", context.Exception?.Message);
						return Task.CompletedTask;
					},
					OnTokenValidated = context =>
					{
						var loggerFactory = context.HttpContext.RequestServices.GetService<ILoggerFactory>();
						var logger = loggerFactory?.CreateLogger("JwtBearer");
						logger?.LogInformation("JWT token validated for user: {User}", context.Principal?.Identity?.Name);
						return Task.CompletedTask;
					}
				};
			});

			return services;
		}
	}
}