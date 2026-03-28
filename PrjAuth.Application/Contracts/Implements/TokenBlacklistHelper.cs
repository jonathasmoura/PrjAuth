using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Configuration;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Implements
{
	public class TokenBlacklistHelper : ITokenBlacklistHelper
	{
		private readonly IHttpContextAccessor _httpContextAccessor;
		private readonly ITokenService _tokenService;
		private readonly ITokenBlackListService _tokenBlackListService;
		private readonly LoadBalancedTokenConfiguration _lbConfig;
		private readonly ILogger<TokenBlacklistHelper> _logger;

		public TokenBlacklistHelper(
			IHttpContextAccessor httpContextAccessor,
			ITokenService tokenService,
			ITokenBlackListService tokenBlackListService,
			LoadBalancedTokenConfiguration lbConfig,
			ILogger<TokenBlacklistHelper> logger)
		{
			_httpContextAccessor = httpContextAccessor;
			_tokenService = tokenService;
			_tokenBlackListService = tokenBlackListService;
			_lbConfig = lbConfig;
			_logger = logger;
		}

		public async Task TryBlacklistCurrentAccessTokenAsync()
		{
			try
			{
				var ctx = _httpContextAccessor?.HttpContext;
				if (ctx == null)
					return;

				var authHeader = ctx.Request?.Headers["Authorization"].FirstOrDefault();
				if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
				{
					var rawToken = authHeader.Substring("Bearer ".Length).Trim();
					var jti = _tokenService.GetJti(rawToken);
					if (!string.IsNullOrEmpty(jti))
					{
						var expiration = _tokenService.GetTokenExpirationUtc(rawToken) ?? DateTime.UtcNow.AddMinutes(1);
						await _tokenBlackListService.BlacklistTokenAsync(jti, expiration);
					}
				}
				else
				{
					var jtiFromUser = ctx.User?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
					if (!string.IsNullOrEmpty(jtiFromUser))
					{
						var expiration = DateTime.UtcNow.AddMinutes(_lbConfig.AccessTokenExpirationMinutes);
						await _tokenBlackListService.BlacklistTokenAsync(jtiFromUser, expiration);
					}
				}
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao tentar colocar jti na blacklist (helper)");
			}
		}
	}
}
