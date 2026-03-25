using FluentAssertions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using PrjAuth.Application.Contracts.Implements;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;

namespace PrjAuth.Application.Tests;

public class AuthServiceTests
{
	[Fact]
	public async Task AuthenticateAsync_WithValidCredentials_ReturnsAuthResponseAndSavesRefreshToken()
	{
		// Arrange
		var login = new LoginUserDto { Email = "u@e.com", Password = "Pass123!" };
		var userDto = new UserDto { Id = Guid.NewGuid(), Username = "u", Email = "u@e.com", Roles = new string[] { "Membro" } };

		var userServiceMock = new Mock<IUserService>();
		userServiceMock.Setup(u => u.ValidateCredentialsAsync(login.Email, login.Password)).ReturnsAsync(new UserCredentialDto { Id = userDto.Id, Username = userDto.Username, Email = userDto.Email, Roles = userDto.Roles });

		var tokenServiceMock = new Mock<ITokenService>();
		tokenServiceMock.Setup(t => t.GenerateAccessToken(It.IsAny<UserDto>())).Returns("access.token");
		tokenServiceMock.Setup(t => t.GenerateRefreshToken()).Returns("refresh.raw");

		var refreshMock = new Mock<IRefreshTokenService>();
		refreshMock.Setup(r => r.SaveRefreshTokenAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>())).Returns(Task.CompletedTask).Verifiable();

		// Criar configuração mínima em memória (evita passar null!)
		var inMemorySettings = new Dictionary<string, string?>
			{
				{ "Jwt:AccessTokenExpirationMinutes", "30" },
				{ "Jwt:Issuer", "test-issuer" },
				{ "Jwt:Audience", "test-audience" },
				{ "Jwt:Key", "test-key" }
			};
		var configuration = new ConfigurationBuilder().AddInMemoryCollection(inMemorySettings).Build();

		// Distributed cache in-memory para testes
		var memoryCacheOptions = Options.Create(new MemoryDistributedCacheOptions());
		IDistributedCache distributedCache = new MemoryDistributedCache(memoryCacheOptions);

		// Logger dummy para passar ao construtor
		var lbLoggerMock = new Mock<ILogger<PrjAuth.Application.Configuration.LoadBalancedTokenConfiguration>>();

		// Criar uma instância real e válida de LoadBalancedTokenConfiguration para o teste
		var lbConfig = new PrjAuth.Application.Configuration.LoadBalancedTokenConfiguration(configuration, distributedCache, lbLoggerMock.Object);

		var tokenSecrets = new PrjAuth.Application.Configuration.TokenSecrets("primary", "secondary");
		var loggerMock = new Mock<Microsoft.Extensions.Logging.ILogger<AuthService>>();

		var svc = new AuthService(tokenServiceMock.Object, userServiceMock.Object, refreshMock.Object, new Mock<ITokenBlackListService>().Object, new Mock<Microsoft.AspNetCore.Http.IHttpContextAccessor>().Object, loggerMock.Object, lbConfig);

		// Act
		var res = await svc.AuthenticateAsync(new LoginUserDto { Email = login.Email, Password = login.Password });

		// Assert
		res.Should().NotBeNull();
		res!.AccessToken.Should().Be("access.token");
		refreshMock.Verify(r => r.SaveRefreshTokenAsync(userDto.Id, "refresh.raw", It.IsAny<string>()), Times.Once);
	}
}
