using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Interfaces;
using System;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Implements
{
	public class TokenBlackListService : ITokenBlackListService
	{
		private readonly IDistributedCache _cache;
		private readonly ILogger<TokenBlackListService> _logger;

		public TokenBlackListService(IDistributedCache cache, ILogger<TokenBlackListService> logger)
		{
			_cache = cache;
			_logger = logger;
		}

		public async Task BlacklistTokenAsync(string jti, DateTime expiration)
		{
			var options = new DistributedCacheEntryOptions
			{
				AbsoluteExpiration = new DateTimeOffset(expiration)
			};

			await _cache.SetStringAsync($"blacklist:{jti}", "true", options);
			_logger.LogInformation("Token {Jti} na lista negra até {Expiration}", jti, expiration);
		}

		public async Task<bool> IsTokenBlacklistedAsync(string jti)
		{
			var blacklistedToken = await _cache.GetStringAsync($"blacklist:{jti}");
			return !string.IsNullOrEmpty(blacklistedToken);
		}
	}
}
