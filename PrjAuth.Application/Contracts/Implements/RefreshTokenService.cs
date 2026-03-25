using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Implements
{
	public class RefreshTokenService : IRefreshTokenService
	{
		private readonly IRefreshTokenRepository _refreshTokenRepository;
		private readonly IUnitOfWork _unitOfWork;
		private readonly ILogger<RefreshTokenService> _logger;

		public RefreshTokenService(IRefreshTokenRepository refreshTokenRepository, IUnitOfWork unitOfWork, ILogger<RefreshTokenService> logger)
		{
			_refreshTokenRepository = refreshTokenRepository ?? throw new ArgumentNullException(nameof(refreshTokenRepository));
			_unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		}

		public async Task<RefreshToken> CreateRefreshTokenAsync(string username, string createdByIp)
		{
			var token = GenerateTokenString();
			var refreshToken = new RefreshToken
			{
				Token = ComputeSha256Hash(token),
				Username = username,
				CreatedAt = DateTime.UtcNow,
				CreatedByIp = createdByIp,
				ExpiresAt = DateTime.UtcNow.AddDays(7),
				Revoked = false
			};

			await _refreshTokenRepository.AddAsync(refreshToken);
			await _unitOfWork.SaveChangesAsync();

			return refreshToken;
		}

		public async Task<(RefreshToken? Replacement, string? RawToken)> RotateRefreshTokenAsync(string existingToken, string createdByIp)
		{
			var current = await _refreshTokenRepository.GetByTokenAsync(existingToken);

			if (current == null || !current.IsActive)
			{
				_logger.LogWarning("Tentativa de rotação de token de atualização inválida. Token encontrado? {HasToken}", current != null);
				throw new SecurityTokenException("Token de atualização inválido");
			}

			if (current.Revoked && !string.IsNullOrEmpty(current.ReplacedByToken))
			{
				_logger.LogWarning("Detecção de reutilização do token de atualização para o usuário {UserId}. Revogando todos os tokens.", current.UserId);

				await _refreshTokenRepository.RevokeAllUserTokensAsync(current.UserId, createdByIp);
				await _unitOfWork.SaveChangesAsync();

				throw new SecurityTokenException("Detecção de reutilização do token. Faça login novamente.");
			}

			var newToken = GenerateTokenString();
			var replacement = new RefreshToken
			{
				Token = ComputeSha256Hash(newToken),
				Username = current.Username,
				UserId = current.UserId,
				CreatedAt = DateTime.UtcNow,
				CreatedByIp = createdByIp,
				ExpiresAt = DateTime.UtcNow.AddDays(7),
				Revoked = false
			};

			current.Revoked = true;
			current.RevokedAt = DateTime.UtcNow;
			current.RevokedByIp = createdByIp;
			current.ReplacedByToken = replacement.Token;

			await _refreshTokenRepository.UpdateAsync(current);
			await _refreshTokenRepository.AddAsync(replacement);
			await _unitOfWork.SaveChangesAsync();

			return (replacement, newToken);
		}

		public async Task<RefreshToken?> GetByTokenAsync(string token)
		{
			return await _refreshTokenRepository.GetByTokenAsync(token);
		}

		public async Task RevokeRefreshTokenAsync(RefreshToken refreshToken, string revokedByIp, string? replacedByToken = null)
		{
			refreshToken.Revoked = true;
			refreshToken.RevokedAt = DateTime.UtcNow;
			refreshToken.RevokedByIp = revokedByIp;
			if (!string.IsNullOrEmpty(replacedByToken))
				refreshToken.ReplacedByToken = ComputeSha256Hash(replacedByToken);

			await _refreshTokenRepository.UpdateAsync(refreshToken);
			await _unitOfWork.SaveChangesAsync();
		}

		public async Task SaveRefreshTokenAsync(Guid userId, string refreshToken, string createdByIp = "")
		{
			var hashed = ComputeSha256Hash(refreshToken);

			var entity = new RefreshToken
			{
				Token = hashed,
				UserId = userId,
				CreatedAt = DateTime.UtcNow,
				CreatedByIp = createdByIp,
				ExpiresAt = DateTime.UtcNow.AddDays(7),
				Revoked = false
			};

			await _refreshTokenRepository.AddAsync(entity);
			await _unitOfWork.SaveChangesAsync();
		}

		private static string GenerateTokenString()
		{
			var randomNumber = new byte[64];
			using var rng = RandomNumberGenerator.Create();
			rng.GetBytes(randomNumber);
			return Convert.ToBase64String(randomNumber);
		}

		private static string ComputeSha256Hash(string raw)
		{
			using var sha = SHA256.Create();
			var bytes = Encoding.UTF8.GetBytes(raw);
			var hash = sha.ComputeHash(bytes);
			return Convert.ToBase64String(hash);
		}
	}
}
