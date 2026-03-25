using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BCrypt.Net;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;

namespace PrjAuth.Application.Contracts.Implements
{
	public class UserService : IUserService
	{
		private readonly IUnitOfWork _unitOfWork;
		private readonly ITokenService _tokenService;
		private readonly IRefreshTokenService _refreshTokenService;

		public UserService(IUnitOfWork unitOfWork, ITokenService tokenService, IRefreshTokenService refreshTokenService)
		{
			_unitOfWork = unitOfWork;
			_tokenService = tokenService;
			_refreshTokenService = refreshTokenService;
		}

		public async Task<UserByEmailDto?> FindUserByEmail(string email)
		{
			var user = await _unitOfWork.Users.GetByEmailAsync(email);
			if (user == null) return null;

			return new UserByEmailDto { Email = user.Email };
		}

		public async Task<UserDto?> FindUserById(Guid id)
		{
			var user = await _unitOfWork.Users.GetByIdAsync(id);
			if (user == null) return null;

			return new UserDto
			{
				Id = user.Id,
				Email = user.Email,
				Username = user.Name,
				Roles = user.Roles.ToArray()
			};
		}

		public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
		{
			var allUsers = await _unitOfWork.Users.GetAllAsync();

			var usersDto = allUsers
				.Select(user => new UserDto
				{
					Id = user.Id,
					Email = user.Email,
					Username = user.Name,
					Roles = user.Roles.ToArray()
				})
				.ToList();

			return usersDto;
		}

		public async Task<LoginResponseDto> LoginUserAsync(LoginUserDto loginUserDto)
		{
			if (loginUserDto == null || string.IsNullOrWhiteSpace(loginUserDto.Email) || string.IsNullOrWhiteSpace(loginUserDto.Password))
			{
				return new LoginResponseDto { Flag = false, Message = "Credenciais inválidas" };
			}

			var userCred = await ValidateCredentialsAsync(loginUserDto.Email, loginUserDto.Password);
			if (userCred == null)
			{
				return new LoginResponseDto { Flag = false, Message = "Usuário ou senha inválidos" };
			}

			var userDto = new UserDto
			{
				Id = userCred.Id,
				Username = userCred.Username,
				Email = userCred.Email,
				Roles = userCred.Roles
			};

			var accessToken = _tokenService.GenerateAccessToken(userDto);
			var refreshToken = _tokenService.GenerateRefreshToken();

			await _refreshTokenService.SaveRefreshTokenAsync(userDto.Id, refreshToken);

			return new LoginResponseDto
			{
				Flag = true,
				Message = "Login realizado com sucesso",
				Token = accessToken
			};
		}

		public async Task<RegisterResponseDto> RegisterUserAsync(RegisterUserDto registerUserDto)
		{
			if (registerUserDto == null)
				return new RegisterResponseDto
				{
					Flag = false,
					Message = "Requisição inválida"
				};

			if (string.IsNullOrWhiteSpace(registerUserDto.Email) ||
				string.IsNullOrWhiteSpace(registerUserDto.Password) ||
				string.IsNullOrWhiteSpace(registerUserDto.Name))
			{
				return new RegisterResponseDto
				{
					Flag = false,
					Message = "Campos obrigatórios ausentes"
				};
			}

			if (!string.Equals(registerUserDto.Password, registerUserDto.ConfirmPassword, StringComparison.Ordinal))
			{
				return new RegisterResponseDto
				{
					Flag = false,
					Message = "As senhas não coincidem"
				};
			}

			var normalizedEmail = registerUserDto.Email.Trim().ToLowerInvariant();

			var userByEmail = await _unitOfWork.Users.GetByEmailAsync(normalizedEmail);

			if (userByEmail != null)
				return new RegisterResponseDto
				{
					Flag = false,
					Message = "Usuário já existe!"
				};

			var passwordHash = BCrypt.Net.BCrypt.HashPassword(registerUserDto.Password);

			var isAdmin = registerUserDto.IsAdmin;
			var roleString = isAdmin ? "Admin" : "Membro";

			var newUser = new User(
				registerUserDto.Name.Trim(),
				registerUserDto.LastName?.Trim(),
				normalizedEmail,
				passwordHash,
				isAdmin,
				new[] { roleString }
			);

			await _unitOfWork.Users.AddAsync(newUser);
			await _unitOfWork.SaveChangesAsync();

			return new RegisterResponseDto
			{
				Flag = true,
				Message = "Usuário registrado com sucesso!"
			};
		}

		public async Task<UserCredentialDto?> ValidateCredentialsAsync(string? email, string? password)
		{
			if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
				return null;

			var user = await _unitOfWork.Users.GetByEmailAsync(email);
			if (user == null) return null;

			var verified = false;
			try
			{
				verified = BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
			}
			catch
			{
				return null;
			}

			if (!verified) return null;

			return new UserCredentialDto
			{
				Id = user.Id,
				Username = user.Name,
				Email = user.Email,
				Roles = user.Roles.ToArray()
			};
		}
	}
}
