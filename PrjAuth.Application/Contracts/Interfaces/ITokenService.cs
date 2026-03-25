using PrjAuth.Application.Dtos;
using PrjAuth.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface ITokenService
	{
		string GenerateAccessToken(UserDto user);
		string GenerateRefreshToken();

		// Removido default para evitar problemas com expression trees / Moq
		ClaimsPrincipal? ValidateToken(string token, bool validateLifetime);

		ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);

		// Helpers centralizados para leitura de claims sem validação de assinatura/lifetime
		DateTime? GetTokenExpirationUtc(string token);

		string? GetJti(string token);
	}
}
