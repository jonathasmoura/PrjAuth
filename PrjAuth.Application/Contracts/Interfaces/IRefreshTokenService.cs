using PrjAuth.Domain.Entities;
using System;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface IRefreshTokenService
	{
		Task<RefreshToken> CreateRefreshTokenAsync(string username, string createdByIp);
		
		Task<(RefreshToken? Replacement, string? RawToken)> RotateRefreshTokenAsync(string existingToken, string createdByIp);
		Task<RefreshToken?> GetByTokenAsync(string token);
		Task RevokeRefreshTokenAsync(RefreshToken refreshToken, string revokedByIp, string? replacedByToken = null);
		Task SaveRefreshTokenAsync(Guid userId, string refreshToken, string createdByIp = "");
		
	}
}
