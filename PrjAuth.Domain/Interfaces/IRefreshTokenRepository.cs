using PrjAuth.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Domain.Interfaces
{
	public interface IRefreshTokenRepository
	{
		Task AddAsync(RefreshToken refreshToken);
		Task<RefreshToken?> GetByTokenAsync(string token);
		Task UpdateAsync(RefreshToken refreshToken);
		Task DeleteAsync(RefreshToken refreshToken);

		// Novo: revoga todos os tokens ativos de um usuário (não salva; a SaveChanges fica com UnitOfWork)
		Task RevokeAllUserTokensAsync(Guid userId, string revokedByIp = "");
	}
}
