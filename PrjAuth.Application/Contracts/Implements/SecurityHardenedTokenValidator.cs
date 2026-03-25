using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Interfaces;
using System.Security.Claims;
using System.Threading.Tasks;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace PrjAuth.Application.Contracts.Implements
{
	public class SecurityHardenedTokenValidator : ITokenValidator
	{
		private readonly ITokenService _tokenService;
		private readonly ITokenBlackListService _blackListService;
		private readonly ILogger<SecurityHardenedTokenValidator> _logger;

		public SecurityHardenedTokenValidator(
			ITokenService tokenService,
			ITokenBlackListService blackListService,
			ILogger<SecurityHardenedTokenValidator> logger)
		{
			_tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
			_blackListService = blackListService ?? throw new ArgumentNullException(nameof(blackListService));
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		}

		public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token)
		{
			if (string.IsNullOrWhiteSpace(token))
				return null;

			try
			{
				// Valida assinatura/lifetime/issuer/audience via TokenService
				var principal = _tokenService.ValidateToken(token, validateLifetime: true);
				if (principal == null) return null;

				// Checa blacklist pelo jti
				var jti = principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
				if (!string.IsNullOrEmpty(jti))
				{
					var isBlacklisted = await _blackListService.IsTokenBlacklistedAsync(jti).ConfigureAwait(false);
					if (isBlacklisted)
					{
						_logger.LogInformation("Token com jti {Jti} está em blacklist", jti);
						return null;
					}
				}

				return principal;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao validar token de forma hardened");
				return null;
			}
		}
	}
}
