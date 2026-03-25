using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace PrjAuth.Application.Contracts.Implements
{
	public class AsymmetricTokenService : ITokenService
	{
		private readonly RSA _rsa;
		private readonly string _keyId;
		private readonly string _issuer;
		private readonly string _audience;
		private readonly int _accessTokenMinutes;

		public AsymmetricTokenService(IConfiguration configuration)
		{
			_rsa = RSA.Create();

			var privateKeyBase64 = configuration["Jwt:PrivateKey"];
			var publicKeyBase64 = configuration["Jwt:PublicKey"];
			_keyId = configuration["Jwt:KeyId"] ?? Guid.NewGuid().ToString();
			_issuer = configuration["Jwt:Issuer"] ?? "your-service";
			_audience = configuration["Jwt:Audience"] ?? "your-api";
			_accessTokenMinutes = int.TryParse(configuration["Jwt:AccessTokenExpirationMinutes"], out var m) ? m : 15;

			if (!string.IsNullOrWhiteSpace(privateKeyBase64))
			{
				var privateBytes = Convert.FromBase64String(privateKeyBase64);
				try
				{
					_rsa.ImportRSAPrivateKey(privateBytes, out _);
				}
				catch
				{
					try
					{
						_rsa.ImportPkcs8PrivateKey(privateBytes, out _);
					}
					catch
					{
					}
				}
			}
			else if (!string.IsNullOrWhiteSpace(publicKeyBase64))
			{
				var publicBytes = Convert.FromBase64String(publicKeyBase64);
				try
				{
					_rsa.ImportSubjectPublicKeyInfo(publicBytes, out _);
				}
				catch
				{
				}
			}
		}

		public string GenerateAccessToken(UserDto user)
		{
			if (user is null) throw new ArgumentNullException(nameof(user));

			var tokenHandler = new JwtSecurityTokenHandler();

			var signingKey = new RsaSecurityKey(_rsa) { KeyId = _keyId };

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(GetClaims(user)),
				Expires = DateTime.UtcNow.AddMinutes(_accessTokenMinutes),
				Issuer = _issuer,
				Audience = _audience,
				SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)
			};

			var token = tokenHandler.CreateToken(tokenDescriptor);
			return tokenHandler.WriteToken(token);
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
				var rsaForValidation = RSA.Create();
				try
				{
					var pubParams = _rsa.ExportParameters(false);
					rsaForValidation.ImportParameters(pubParams);
				}
				catch
				{
					return null;
				}

				var validationParameters = new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = new RsaSecurityKey(rsaForValidation) { KeyId = _keyId },
					ValidateIssuer = true,
					ValidIssuer = _issuer,
					ValidateAudience = true,
					ValidAudience = _audience,
					ValidateLifetime = validateLifetime,
					ClockSkew = TimeSpan.FromMinutes(1)
				};

				var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

				if (validatedToken is JwtSecurityToken jwtToken)
				{
					var alg = jwtToken.Header.Alg ?? string.Empty;
					if (!alg.Equals(SecurityAlgorithms.RsaSha256, StringComparison.InvariantCultureIgnoreCase)
						&& !alg.Equals(SecurityAlgorithms.RsaSha256Signature, StringComparison.InvariantCultureIgnoreCase))
					{
						return null;
					}
				}

				return principal;
			}
			catch
			{
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
					return DateTimeOffset.FromUnixTimeSeconds(exp.Value).UtcDateTime;

				var expClaim = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
				if (long.TryParse(expClaim, out var expSeconds))
					return DateTimeOffset.FromUnixTimeSeconds(expSeconds).UtcDateTime;

				return null;
			}
			catch
			{
				return null;
			}
		}

		public string? GetJti(string token)
		{
			if (string.IsNullOrWhiteSpace(token)) return null;

			try
			{
				var principal = ValidateToken(token, validateLifetime: false);
				if (principal == null) return null;

				return principal.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
			}
			catch
			{
				return null;
			}
		}

		private IEnumerable<Claim> GetClaims(UserDto user)
		{
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

			return claims;
		}
	}
}
