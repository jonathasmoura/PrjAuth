using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Moq;
using PrjAuth.Application.Contracts.Implements;
using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;

namespace PrjAuth.Application.Tests;

public class RefreshTokenServiceTests
{
	[Fact]
	public async Task CreateRefreshTokenAsync_PersistsAndReturnsHashedToken()
	{
		// Arrange
		var repoMock = new Mock<IRefreshTokenRepository>();
		var unitMock = new Mock<IUnitOfWork>();

		// SaveChangesAsync recebe CancellationToken — usar It.IsAny<CancellationToken>() para compatibilidade
		unitMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

		RefreshToken? captured = null;
		repoMock.Setup(r => r.AddAsync(It.IsAny<RefreshToken>()))
			.Callback<RefreshToken>(rt => captured = rt)
			.Returns(Task.CompletedTask);

		var svc = new RefreshTokenService(repoMock.Object, unitMock.Object, new NullLogger<RefreshTokenService>());

		// Act
		var result = await svc.CreateRefreshTokenAsync("username", "127.0.0.1");

		// Assert
		result.Should().NotBeNull();
		captured.Should().NotBeNull();
		captured!.Token.Should().NotBeNullOrEmpty();
		captured.Username.Should().Be("username");

		// o objeto retornado deve ter o mesmo hash persistido
		result.Token.Should().Be(captured.Token);
	}

	[Fact]
	public async Task RotateRefreshTokenAsync_InvalidToken_ThrowsSecurityTokenException()
	{
		// Arrange
		var repoMock = new Mock<IRefreshTokenRepository>();
		repoMock.Setup(r => r.GetByTokenAsync(It.IsAny<string>())).ReturnsAsync((RefreshToken?)null);

		var unitMock = new Mock<IUnitOfWork>();
		unitMock.Setup(u => u.SaveChangesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(1);

		var svc = new RefreshTokenService(repoMock.Object, unitMock.Object, new NullLogger<RefreshTokenService>());

		// Act / Assert
		await Assert.ThrowsAsync<SecurityTokenException>(async () =>
			await svc.RotateRefreshTokenAsync("nonexistent", "127.0.0.1"));
	}
}
