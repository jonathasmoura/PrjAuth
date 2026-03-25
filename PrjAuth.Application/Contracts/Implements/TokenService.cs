using Microsoft.Extensions.Logging;
using PrjAuth.Application.Configuration;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace PrjAuth.Application.Contracts.Implements
{
	public class TokenService : ITokenService
	{
		private readonly LoadBalancedTokenConfiguration _lbConfig;
		private readonly ILogger<TokenService> _logger;
		private readonly string _primarySecret;
		private readonly string _secondarySecret;

		public TokenService(LoadBalancedTokenConfiguration lbConfig, TokenSecrets tokenSecrets, ILogger<TokenService> logger)
		{
			_lbConfig = lbConfig ?? throw new ArgumentNullException(nameof(lbConfig));
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));

			_primarySecret = tokenSecrets?.Primary ?? string.Empty;
			_secondarySecret = tokenSecrets?.Secondary ?? string.Empty;
		}

		public string GenerateAccessToken(UserDto user)
		{
			if (user is null) throw new ArgumentNullException(nameof(user));

			var key = Encoding.UTF8.GetBytes(_primarySecret);

			var tokenHandler = new JwtSecurityTokenHandler();

			var claims = new List<Claim>
			{
				new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
				new Claim(ClaimTypes.Name, user.Username ?? string.Empty),
				new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				new Claim(JwtRegisteredClaimNames.Iat,
					new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
					ClaimValueTypes.Integer64)
			};

			if (user.Roles != null)
			{
				foreach (var role in user.Roles)
				{
					claims.Add(new Claim(ClaimTypes.Role, role));
				}
			}

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(claims),
				Expires = DateTime.UtcNow.AddMinutes(_lbConfig.AccessTokenExpirationMinutes),
				Issuer = _lbConfig.Issuer,
				Audience = _lbConfig.Audience,
				SigningCredentials = new SigningCredentials(
					new SymmetricSecurityKey(key),
					SecurityAlgorithms.HmacSha256)
			};

			var token = tokenHandler.CreateToken(tokenDescriptor);
			var tokenString = tokenHandler.WriteToken(token);

			_logger.LogInformation("Token de acesso gerado para o usuário {Username}", user.Username);

			return tokenString;
		}

		public string GenerateRefreshToken()
		{
			var randomNumber = new byte[64];
			using var rng = RandomNumberGenerator.Create();
			rng.GetBytes(randomNumber);
			return Convert.ToBase64String(randomNumber);
		}

		public ClaimsPrincipal? ValidateToken(string token, bool validateLifetime)
		{
			if (string.IsNullOrWhiteSpace(token)) return null;

			var tokenHandler = new JwtSecurityTokenHandler();

			try
			{
				JwtSecurityToken preToken;
				try
				{
					preToken = tokenHandler.ReadJwtToken(token);
				}
				catch
				{
					_logger.LogWarning("Token malformado ao tentar ler header.");
					return null;
				}

				var preAlg = preToken?.Header.Alg ?? string.Empty;
				if (!preAlg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase)
					&& !preAlg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.InvariantCultureIgnoreCase))
				{
					_logger.LogWarning("Algoritmo de assinatura inválido no header do token: {Alg}", preAlg);
					return null;
				}

				var primary = _primarySecret;
				var secondary = _secondarySecret;

				var validationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					ValidateIssuer = true,
					ValidIssuer = _lbConfig.Issuer,
					ValidateAudience = true,
					ValidAudience = _lbConfig.Audience,
					ValidateLifetime = validateLifetime,
					ClockSkew = TimeSpan.FromMinutes(1),
					IssuerSigningKeyResolver = (tokenString, securityToken, kid, parameters) =>
					{
						var keys = new List<SecurityKey>();
						if (!string.IsNullOrWhiteSpace(primary))
						{
							keys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(primary)));
						}
						if (!string.IsNullOrWhiteSpace(secondary))
						{
							keys.Add(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secondary)));
						}
						return keys;
					}
				};

				var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

				if (validatedToken is JwtSecurityToken jwtToken)
				{
					var alg = jwtToken.Header.Alg ?? string.Empty;
					if (!alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase)
						&& !alg.Equals(SecurityAlgorithms.HmacSha256Signature, StringComparison.InvariantCultureIgnoreCase))
					{
						_logger.LogWarning("Falha na validação do token: Algoritmo inválido {Algorithm}", jwtToken.Header.Alg);
						return null;
					}
				}

				return principal;
			}
			catch (SecurityTokenException ex)
			{
				_logger.LogWarning(ex, "Falha na validação do token");
				return null;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Erro inesperado na validação do token");
				return null;
			}
		}

		public ClaimsPrincipal? GetPrincipalFromExpiredToken(string token)
		{
			return ValidateToken(token, validateLifetime: false);
		}

		public DateTime? GetTokenExpirationUtc(string token)
		{
			if (string.IsNullOrWhiteSpace(token)) return null;

			try
			{
				var principal = ValidateToken(token, validateLifetime: false);
				if (principal == null) return null;

				var handler = new JwtSecurityTokenHandler();
				var jwt = handler.ReadJwtToken(token);

				var exp = jwt.Payload.Expiration;
				if (exp.HasValue)
				{
					return DateTimeOffset.FromUnixTimeSeconds(exp.Value).UtcDateTime;
				}

				var expClaim = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
				if (long.TryParse(expClaim, out var expSeconds))
				{
					return DateTimeOffset.FromUnixTimeSeconds(expSeconds).UtcDateTime;
				}

				return null;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao ler exp do token");
				return null;
			}
		}

		public string? GetJti(string token)
		{
			if (string.IsNullOrWhiteSpace(token)) return null;

			try
			{
				var principal = ValidateToken(token, validateLifetime: false);
				var jti = principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
				if (!string.IsNullOrWhiteSpace(jti)) return jti;

				return null;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao ler jti do token");
				return null;
			}
		}
	}
}
