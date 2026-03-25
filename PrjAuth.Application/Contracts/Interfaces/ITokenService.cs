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
		ClaimsPrincipal? ValidateToken(string token, bool validateLifetime);
		ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);

		DateTime? GetTokenExpirationUtc(string token);

		string? GetJti(string token);
	}
}
