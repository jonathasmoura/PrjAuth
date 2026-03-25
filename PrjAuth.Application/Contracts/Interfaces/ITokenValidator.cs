using System.Security.Claims;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface ITokenValidator
	{
		Task<ClaimsPrincipal?> ValidateTokenAsync(string token);
	}
}
