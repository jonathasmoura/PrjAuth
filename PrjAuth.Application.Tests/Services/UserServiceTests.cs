using FluentAssertions;
using Moq;
using PrjAuth.Application.Contracts.Implements;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Tests.Services
{
	public class UserServiceTests
	{
		[Fact]
		public async Task LoginUserAsync_WithValidCredentials_GeneratesTokensAndSavesRefreshToken()
		{
			// Arrange
			var email = "teste.com";
			var plain = "Pass123!";
			var passwordHash = BCrypt.Net.BCrypt.HashPassword(plain);

			// cria entidade User conforme construtor do domínio
			var user = new User("Name", "Last", email, passwordHash, false, new[] { "Membro" });

			var userRepoMock = new Mock<IUserRepository>();
			userRepoMock.Setup(r => r.GetByEmailAsync(email)).ReturnsAsync(user);

			var unitMock = new Mock<IUnitOfWork>();
			unitMock.Setup(u => u.Users).Returns(userRepoMock.Object);

			var tokenServiceMock = new Mock<ITokenService>();
			tokenServiceMock.Setup(t => t.GenerateAccessToken(It.IsAny<UserDto>())).Returns("access.token");
			tokenServiceMock.Setup(t => t.GenerateRefreshToken()).Returns("refresh.raw");

			var refreshMock = new Mock<IRefreshTokenService>();
			refreshMock.Setup(r => r.SaveRefreshTokenAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>())).Returns(Task.CompletedTask).Verifiable();

			var svc = new UserService(unitMock.Object, tokenServiceMock.Object, refreshMock.Object);

			var dto = new LoginUserDto { Email = email, Password = plain };

			// Act
			var res = await svc.LoginUserAsync(dto);

			// Assert
			res.Should().NotBeNull();
			res.Flag.Should().BeTrue();
			res.Token.Should().Be("access.token");
			refreshMock.Verify(r => r.SaveRefreshTokenAsync(user.Id, "refresh.raw", It.IsAny<string>()), Times.Once);
		}

		[Fact]
		public async Task LoginUserAsync_WithInvalidPassword_ReturnsFlagFalse()
		{
			// Arrange
			var email = "u@e.com";
			var correctPassword = "Pass123!";
			var wrongPassword = "Wrong!";
			var passwordHash = BCrypt.Net.BCrypt.HashPassword(correctPassword);

			var user = new User("Name", "Last", email, passwordHash, false, new[] { "Membro" });

			var userRepoMock = new Mock<IUserRepository>();
			userRepoMock.Setup(r => r.GetByEmailAsync(email)).ReturnsAsync(user);

			var unitMock = new Mock<IUnitOfWork>();
			unitMock.Setup(u => u.Users).Returns(userRepoMock.Object);

			var tokenServiceMock = new Mock<ITokenService>();
			var refreshMock = new Mock<IRefreshTokenService>();

			var svc = new UserService(unitMock.Object, tokenServiceMock.Object, refreshMock.Object);

			var dto = new LoginUserDto { Email = email, Password = wrongPassword };

			// Act
			var res = await svc.LoginUserAsync(dto);

			// Assert
			res.Should().NotBeNull();
			res.Flag.Should().BeFalse();
			res.Message.Should().Be("Usuário ou senha inválidos");
		}

		[Fact]
		public async Task RegisterUserAsync_WhenUserAlreadyExists_ReturnsFlagFalse()
		{
			// Arrange
			var email = "u@e.com";
			var existingUser = new User("N", "L", email, "hash", false, new[] { "Membro" });

			var userRepoMock = new Mock<IUserRepository>();

			// Serviço normaliza o email (Trim + ToLowerInvariant) antes de consultar o repositório.
			// Ajuste o mock para corresponder ao email normalizado.
			var normalizedEmail = email.Trim().ToLowerInvariant();
			userRepoMock.Setup(r => r.GetByEmailAsync(normalizedEmail)).ReturnsAsync(existingUser);

			var unitMock = new Mock<IUnitOfWork>();
			unitMock.Setup(u => u.Users).Returns(userRepoMock.Object);

			var tokenServiceMock = new Mock<ITokenService>();
			var refreshMock = new Mock<IRefreshTokenService>();

			var svc = new UserService(unitMock.Object, tokenServiceMock.Object, refreshMock.Object);

			var dto = new RegisterUserDto
			{
				Email = email,
				Name = "Name",
				LastName = "Last",
				Password = "Pass123!",
				ConfirmPassword = "Pass123!",
				IsAdmin = false
			};

			// Act
			var res = await svc.RegisterUserAsync(dto);

			// Assert
			res.Should().NotBeNull();
			res.Flag.Should().BeFalse();
			res.Message.Should().Be("Usuário já existe!");
		}

		[Fact]
		public async Task RegisterUserAsync_WithNullRequest_ReturnsFlagFalse()
		{
			// Arrange
			var unitMock = new Mock<IUnitOfWork>();
			var tokenServiceMock = new Mock<ITokenService>();
			var refreshMock = new Mock<IRefreshTokenService>();

			var svc = new UserService(unitMock.Object, tokenServiceMock.Object, refreshMock.Object);

			// Act
			var res = await svc.RegisterUserAsync(null!);

			// Assert
			res.Should().NotBeNull();
			res.Flag.Should().BeFalse();
			res.Message.Should().Be("Requisição inválida");
		}

		[Fact]
		public async Task RegisterUserAsync_WithMissingFields_ReturnsFlagFalse()
		{
			// Arrange
			var unitMock = new Mock<IUnitOfWork>();
			var tokenServiceMock = new Mock<ITokenService>();
			var refreshMock = new Mock<IRefreshTokenService>();

			var svc = new UserService(unitMock.Object, tokenServiceMock.Object, refreshMock.Object);

			var dto = new RegisterUserDto
			{
				Email = "   ", // invalid / whitespace
				Name = "",     // missing name
				Password = "Pass123!",
				ConfirmPassword = "Pass123!",
				IsAdmin = false
			};

			// Act
			var res = await svc.RegisterUserAsync(dto);

			// Assert
			res.Should().NotBeNull();
			res.Flag.Should().BeFalse();
			res.Message.Should().Be("Campos obrigatórios ausentes");
		}

		[Fact]
		public async Task RegisterUserAsync_PasswordsDoNotMatch_ReturnsFlagFalse()
		{
			// Arrange
			var unitMock = new Mock<IUnitOfWork>();
			var tokenServiceMock = new Mock<ITokenService>();
			var refreshMock = new Mock<IRefreshTokenService>();

			var svc = new UserService(unitMock.Object, tokenServiceMock.Object, refreshMock.Object);

			var dto = new RegisterUserDto
			{
				Email = "user@ex.com",
				Name = "Name",
				LastName = "Last",
				Password = "Pass123!",
				ConfirmPassword = "Different123!",
				IsAdmin = false
			};

			// Act
			var res = await svc.RegisterUserAsync(dto);

			// Assert
			res.Should().NotBeNull();
			res.Flag.Should().BeFalse();
			res.Message.Should().Be("As senhas não coincidem");
		}
	}
}
