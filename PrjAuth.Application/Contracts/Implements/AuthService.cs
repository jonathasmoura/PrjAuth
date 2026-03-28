using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using PrjAuth.Application.Configuration;

namespace PrjAuth.Application.Contracts.Implements
{
	public class AuthService : IAuthService
	{
		private readonly ITokenService _tokenService;
		private readonly IUserService _userService;
		private readonly IRefreshTokenService _refreshTokenService;
		private readonly ITokenBlackListService _tokenBlackListService;
		private readonly ILogger<AuthService> _logger;
		private readonly LoadBalancedTokenConfiguration _lbConfig;
		private readonly IClientIpExtractor _clientIpExtractor;
		private readonly ITokenBlacklistHelper _tokenBlacklistHelper;

		public AuthService(
			ITokenService tokenService,
			IUserService userService,
			IRefreshTokenService refreshTokenService,
			ITokenBlackListService tokenBlackListService,
			IClientIpExtractor clientIpExtractor,
			ITokenBlacklistHelper tokenBlacklistHelper,
			ILogger<AuthService> logger,
			LoadBalancedTokenConfiguration lbConfig)
		{
			_tokenService = tokenService;
			_userService = userService;
			_refreshTokenService = refreshTokenService;
			_tokenBlackListService = tokenBlackListService;
			_clientIpExtractor = clientIpExtractor;
			_tokenBlacklistHelper = tokenBlacklistHelper;
			_logger = logger;
			_lbConfig = lbConfig;
		}

		public async Task<AuthResponseDto?> AuthenticateAsync(LoginUserDto request)
		{
			var user = await _userService.ValidateCredentialsAsync(request.Email, request.Password);
			if (user == null)
			{
				_logger.LogWarning("Falha na autenticação para o usuário: {Username}", request.Email);
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

			_logger.LogInformation("Usuário {Username} autenticado com sucesso", user.Username);

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

		public async Task<AuthResponseDto?> RefreshTokenAsync(string refreshToken)
		{
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				_logger.LogWarning("RefreshTokenAsync chamado com token em branco");
				return null;
			}

			var current = await _refreshTokenService.GetByTokenAsync(refreshToken);
			if (current == null || !current.IsActive)
			{
				_logger.LogWarning("Refresh token inválido ou inativo");
				return null;
			}

			var ip = _clientIpExtractor.GetClientIp();

			try
			{
				var (replacement, newRaw) = await _refreshTokenService.RotateRefreshTokenAsync(refreshToken, ip);

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
			catch (SecurityTokenException ste)
			{
				_logger.LogWarning(ste, "Falha ao rotacionar refresh token: {Message}", ste.Message);
				return null;
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Erro inesperado ao rotacionar refresh token");
				return null;
			}
		}

		public async Task<bool> RevokeTokenAsync(string refreshToken)
		{
			if (string.IsNullOrWhiteSpace(refreshToken))
				return false;

			var token = await _refreshTokenService.GetByTokenAsync(refreshToken);
			if (token == null || !token.IsActive)
				return false;

			var ip = _clientIpExtractor.GetClientIp();

			await _refreshTokenService.RevokeRefreshTokenAsync(token, ip);

			await _tokenBlacklistHelper.TryBlacklistCurrentAccessTokenAsync();

			return true;
		}
	}
}
