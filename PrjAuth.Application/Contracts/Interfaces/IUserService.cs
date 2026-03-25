using PrjAuth.Application.Dtos;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface IUserService
	{
		Task<RegisterResponseDto> RegisterUserAsync(RegisterUserDto registerUserDto);
		Task<LoginResponseDto> LoginUserAsync(LoginUserDto loginUserDto);
		Task<UserByEmailDto?> FindUserByEmail(string email);
		Task<UserDto?> FindUserById(Guid id);
		Task<IEnumerable<UserDto>> GetAllUsersAsync();
		Task<UserCredentialDto?> ValidateCredentialsAsync(string? email, string? password);
	}
}
