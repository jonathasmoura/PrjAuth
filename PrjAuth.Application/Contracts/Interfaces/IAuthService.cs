using Microsoft.AspNetCore.Identity.Data;
using PrjAuth.Application.Dtos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface IAuthService
	{
		Task<AuthResponseDto?> AuthenticateAsync(LoginUserDto request);
		Task<AuthResponseDto?> RefreshTokenAsync(string refreshToken);
		Task<bool> RevokeTokenAsync(string refreshToken);
	}
}
