using Microsoft.AspNetCore.Identity.Data;
using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.IdentityModel.Tokens.Jwt;
using PrjAuth.Application.Configuration;

namespace PrjAuth.Application.Contracts.Implements
{
	public class AuthService : IAuthService
	{
		private readonly ITokenService _tokenService ;
		private readonly IUserService _userService;
		private readonly IRefreshTokenService _refreshTokenService;
		private readonly ITokenBlackListService _tokenBlackListService;
		private readonly ILogger<AuthService> _logger;
		private readonly IHttpContextAccessor _httpContextAccessor;
		private readonly LoadBalancedTokenConfiguration _lbConfig;

		public AuthService(
			ITokenService tokenService,
			IUserService userService,
			IRefreshTokenService refreshTokenService,
			ITokenBlackListService tokenBlackListService,
			IHttpContextAccessor httpContextAccessor,
			ILogger<AuthService> logger,
			LoadBalancedTokenConfiguration lbConfig)
		{
			_tokenService = tokenService;
			_userService = userService;
			_refreshTokenService = refreshTokenService;
			_tokenBlackListService = tokenBlackListService;
			_httpContextAccessor = httpContextAccessor;
			_logger = logger;
			_lbConfig = lbConfig;
		}

		public async Task<AuthResponseDto?> AuthenticateAsync(LoginUserDto request)
		{
			{
				var user = await _userService.ValidateCredentialsAsync(request.Email, request.Password);
				if (user == null)
				{
					_logger.LogWarning("Authentication failed for username: {Username}", request.Email);
					return null;
				}
				var userDto = new UserDto
				{
					Id = user.Id,
					Username = user.Username,
					Email = user.Email,
					Roles = user.Roles
				};

				var accessToken = _tokenService.GenerateAccessToken(userDto);
				var refreshToken = _tokenService.GenerateRefreshToken();

				await _refreshTokenService.SaveRefreshTokenAsync(user.Id, refreshToken);

				_logger.LogInformation("User {Username} authenticated successfully", user.Username);

				return new AuthResponseDto
				{
					AccessToken = accessToken,
					RefreshToken = refreshToken,
					ExpiresAt = DateTime.UtcNow.AddMinutes(_lbConfig.AccessTokenExpirationMinutes),
					User = new UserDto
					{
						Id = user.Id,
						Username = user.Username,
						Email = user.Email,
						Roles = user.Roles
					}
				};
			}
		}

		public async Task<AuthResponseDto?> RefreshTokenAsync(string refreshToken)
		{
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				_logger.LogWarning("RefreshTokenAsync called with empty token");
				return null;
			}

			var current = await _refreshTokenService.GetByTokenAsync(refreshToken);
			if (current == null || !current.IsActive)
			{
				_logger.LogWarning("Refresh token inválido ou inativo");
				return null;
			}

			var ip = _httpContextAccessor?.HttpContext?.Request?.Headers["X-Forwarded-For"].FirstOrDefault()
				?? _httpContextAccessor?.HttpContext?.Connection?.RemoteIpAddress?.ToString()
				?? string.Empty;

			( var replacement, var newRaw ) = await _refreshTokenService.RotateRefreshTokenAsync(refreshToken, ip);

			if (replacement == null || string.IsNullOrEmpty(newRaw))
			{
				_logger.LogWarning("Falha ao rotacionar refresh token");
				return null;
			}

			var userDto = await _userService.FindUserById(replacement.UserId);
			if (userDto == null)
			{
				_logger.LogWarning("Usuário do refresh token não encontrado: {UserId}", replacement.UserId);
				return null;
			}

			var accessToken = _tokenService.GenerateAccessToken(userDto);

			return new AuthResponseDto
			{
				AccessToken = accessToken,
				RefreshToken = newRaw,
				ExpiresAt = DateTime.UtcNow.AddMinutes(_lbConfig.AccessTokenExpirationMinutes),
				User = userDto
			};
		}

		public async Task<bool> RevokeTokenAsync(string refreshToken)
		{
			if (string.IsNullOrWhiteSpace(refreshToken))
				return false;

			var token = await _refreshTokenService.GetByTokenAsync(refreshToken);
			if (token == null || !token.IsActive)
				return false;

			var ip = _httpContextAccessor?.HttpContext?.Request?.Headers["X-Forwarded-For"].FirstOrDefault()
				?? _httpContextAccessor?.HttpContext?.Connection?.RemoteIpAddress?.ToString()
				?? string.Empty;

			await _refreshTokenService.RevokeRefreshTokenAsync(token, ip);

			try
			{
				var authHeader = _httpContextAccessor?.HttpContext?.Request?.Headers["Authorization"].FirstOrDefault();
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
					var jtiFromUser = _httpContextAccessor?.HttpContext?.User?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
					if (!string.IsNullOrEmpty(jtiFromUser))
					{
						var expiration = DateTime.UtcNow.AddMinutes(_lbConfig.AccessTokenExpirationMinutes);
						await _tokenBlackListService.BlacklistTokenAsync(jtiFromUser, expiration);
					}
				}
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao tentar colocar jti na blacklist durante logout");
			}

			return true;
		}
	}
}
