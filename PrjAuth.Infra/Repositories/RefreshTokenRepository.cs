using Microsoft.EntityFrameworkCore;
using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;
using PrjAuth.Infra.DataContexts;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System;

namespace PrjAuth.Infra.Repositories
{
	public class RefreshTokenRepository : IRefreshTokenRepository
	{
		private readonly DbAuthContext _dbAuthContext;

		public RefreshTokenRepository(DbAuthContext dbAuthContext)
		{
			_dbAuthContext = dbAuthContext;
		}

		public Task AddAsync(RefreshToken refreshToken)
		{
			_dbAuthContext.RefreshTokens.Add(refreshToken);
			// Commit ficará a cargo do UnitOfWork / camada de aplicação
			return Task.CompletedTask;
		}

		public async Task<RefreshToken?> GetByTokenAsync(string token)
		{
			var hashed = ComputeSha256Hash(token);

			return await _dbAuthContext.RefreshTokens
				.AsNoTracking()
				.FirstOrDefaultAsync(r => r.Token == hashed);
		}

		public Task UpdateAsync(RefreshToken refreshToken)
		{
			_dbAuthContext.RefreshTokens.Update(refreshToken);
			// Commit ficará a cargo do UnitOfWork / camada de aplicação
			return Task.CompletedTask;
		}

		public Task DeleteAsync(RefreshToken refreshToken)
		{
			_dbAuthContext.RefreshTokens.Remove(refreshToken);
			// Commit ficará a cargo do UnitOfWork / camada de aplicação
			return Task.CompletedTask;
		}

		// Novo: revoga todos os tokens não revogados do usuário
		public Task RevokeAllUserTokensAsync(Guid userId, string revokedByIp = "")
		{
			var tokens = _dbAuthContext.RefreshTokens
				.Where(r => r.UserId == userId && !r.Revoked)
				.ToList();

			if (!tokens.Any()) return Task.CompletedTask;

			foreach (var t in tokens)
			{
				t.Revoked = true;
				t.RevokedAt = DateTime.UtcNow;
				t.RevokedByIp = revokedByIp ?? string.Empty;
			}

			_dbAuthContext.RefreshTokens.UpdateRange(tokens);
			// Commit ficará a cargo do UnitOfWork / camada de aplicação
			return Task.CompletedTask;
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
