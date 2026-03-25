using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PrjAuth.Application.Dtos;
using System;
using System.Text.Json;
using System.Threading.Tasks;

namespace PrjAuth.Application.Configuration
{
	public class LoadBalancedTokenConfiguration
	{
		private readonly JwtSettingsDto _settings;
		private readonly IDistributedCache _cache;
		private readonly ILogger<LoadBalancedTokenConfiguration> _logger;

		public LoadBalancedTokenConfiguration(IConfiguration configuration, IDistributedCache cache, ILogger<LoadBalancedTokenConfiguration> logger)
		{
			_cache = cache ?? throw new ArgumentNullException(nameof(cache));
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));

			var jwtSettings = new JwtSettingsDto();
			var sectionFull = configuration.GetSection("JwtSettings");
			var sectionShort = configuration.GetSection("Jwt");

			if (sectionFull.Exists())
			{
				sectionFull.Bind(jwtSettings);
			}
			else if (sectionShort.Exists())
			{
				jwtSettings.SecretKey = sectionShort["Key"] ?? sectionShort["SecretKey"] ?? string.Empty;
				jwtSettings.Issuer = sectionShort["Issuer"] ?? string.Empty;
				jwtSettings.Audience = sectionShort["Audience"] ?? string.Empty;
				jwtSettings.AccessTokenExpirationMinutes = int.TryParse(sectionShort["AccessTokenExpirationMinutes"], out var m) ? m : jwtSettings.AccessTokenExpirationMinutes;
				jwtSettings.RefreshTokenExpirationDays = int.TryParse(sectionShort["RefreshTokenExpirationDays"], out var d) ? d : jwtSettings.RefreshTokenExpirationDays;
			}
			else
			{
				_logger.LogWarning("Nenhuma configuração JWT encontrada. Usando valores padrão em memória.");
			}

			_settings = jwtSettings;
		}

		public async Task<string> GetPrimarySecretAsync()
		{
			try
			{
				var cached = await _cache.GetStringAsync("lb:primarySecret").ConfigureAwait(false);
				if (!string.IsNullOrWhiteSpace(cached))
				{
					return cached;
				}
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao obter primary secret do cache distribuído. Usando configuração local.");
			}

			return _settings.SecretKey ?? string.Empty;
		}

		public async Task<string> GetSecondarySecretAsync()
		{
			try
			{
				var cached = await _cache.GetStringAsync("lb:secondarySecret").ConfigureAwait(false);
				if (!string.IsNullOrWhiteSpace(cached))
				{
					return cached;
				}
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao obter secondary secret do cache distribuído. Usando configuração local.");
			}

			return string.Empty;
		}

		public int AccessTokenExpirationMinutes => _settings.AccessTokenExpirationMinutes;
		public string Issuer => _settings.Issuer ?? string.Empty;
		public string Audience => _settings.Audience ?? string.Empty;
		public int RefreshTokenExpirationDays => _settings.RefreshTokenExpirationDays;
	}
}
