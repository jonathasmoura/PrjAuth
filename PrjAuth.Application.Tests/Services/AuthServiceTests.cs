using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using PrjAuth.Application.Contracts.Implements;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using PrjAuth.Domain.Entities;
using Microsoft.IdentityModel.Tokens;

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
		userServiceMock.Setup(u => u.ValidateCredentialsAsync(login.Email, login.Password))
			.ReturnsAsync(new UserCredentialDto { Id = userDto.Id, Username = userDto.Username, Email = userDto.Email, Roles = userDto.Roles });

		var tokenServiceMock = new Mock<ITokenService>();
		tokenServiceMock.Setup(t => t.GenerateAccessToken(It.IsAny<UserDto>())).Returns("access.token");
		tokenServiceMock.Setup(t => t.GenerateRefreshToken()).Returns("refresh.raw");

		var refreshMock = new Mock<IRefreshTokenService>();
		refreshMock.Setup(r => r.SaveRefreshTokenAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<string>()))
			.Returns(Task.CompletedTask).Verifiable();

		var lbConfig = PrjAuth.Application.Tests.TestHelpers.TestHelpers.CreateLoadBalancedTokenConfiguration();
		var loggerMock = new Mock<ILogger<AuthService>>();

		var tokenBlackListServiceMock = new Mock<ITokenBlackListService>();
		var clientIpExtractorMock = new Mock<IClientIpExtractor>();
		var tokenBlacklistHelperMock = new Mock<ITokenBlacklistHelper>();

		var svc = new AuthService(
			tokenServiceMock.Object,
			userServiceMock.Object,
			refreshMock.Object,
			tokenBlackListServiceMock.Object,
			clientIpExtractorMock.Object,
			tokenBlacklistHelperMock.Object,
			loggerMock.Object,
			lbConfig);

		// Act
		var res = await svc.AuthenticateAsync(new LoginUserDto { Email = login.Email, Password = login.Password });

		// Assert
		res.Should().NotBeNull();
		res!.AccessToken.Should().Be("access.token");
		refreshMock.Verify(r => r.SaveRefreshTokenAsync(userDto.Id, "refresh.raw", It.IsAny<string>()), Times.Once);

		clientIpExtractorMock.Verify(c => c.GetClientIp(), Times.Never);
		tokenBlacklistHelperMock.Verify(t => t.TryBlacklistCurrentAccessTokenAsync(), Times.Never);
	}

	[Fact]
	public async Task RefreshTokenAsync_WithValidRefreshToken_RotatesAndReturnsAuthResponse_AndCallsClientIpExtractor()
	{
		// Arrange
		var existingRaw = "existing.raw";
		var newRaw = "new.raw";
		var userId = Guid.NewGuid();
		var username = "u";

		var userServiceMock = new Mock<IUserService>();
		userServiceMock.Setup(u => u.FindUserById(It.IsAny<Guid>()))
			.ReturnsAsync(new UserDto { Id = userId, Username = username, Email = "u@e.com", Roles = Array.Empty<string>() });

		var tokenServiceMock = new Mock<ITokenService>();
		tokenServiceMock.Setup(t => t.GenerateAccessToken(It.IsAny<UserDto>())).Returns("new.access");

		var refreshMock = new Mock<IRefreshTokenService>();

		var existingRefresh = new RefreshToken
		{
			Id = 1,
			Token = "hashed-existing",
			UserId = userId,
			Username = username,
			CreatedAt = DateTime.UtcNow,
			CreatedByIp = "127.0.0.1",
			ExpiresAt = DateTime.UtcNow.AddHours(1),
			Revoked = false
		};
		refreshMock.Setup(r => r.GetByTokenAsync(existingRaw)).ReturnsAsync(existingRefresh);

		var replacementRefresh = new RefreshToken
		{
			Id = 2,
			Token = "hashed-new",
			UserId = userId,
			Username = username,
			CreatedAt = DateTime.UtcNow,
			CreatedByIp = "127.0.0.1",
			ExpiresAt = DateTime.UtcNow.AddHours(1),
			Revoked = false
		};

		refreshMock.Setup(r => r.RotateRefreshTokenAsync(existingRaw, "127.0.0.1"))
			.ReturnsAsync((replacementRefresh, newRaw));

		var tokenBlackListServiceMock = new Mock<ITokenBlackListService>();
		var clientIpExtractorMock = new Mock<IClientIpExtractor>();
		clientIpExtractorMock.Setup(c => c.GetClientIp()).Returns("127.0.0.1");
		var tokenBlacklistHelperMock = new Mock<ITokenBlacklistHelper>();

		var lbConfig = PrjAuth.Application.Tests.TestHelpers.TestHelpers.CreateLoadBalancedTokenConfiguration();
		var loggerMock = new Mock<ILogger<AuthService>>();

		var svc = new AuthService(
			tokenServiceMock.Object,
			userServiceMock.Object,
			refreshMock.Object,
			tokenBlackListServiceMock.Object,
			clientIpExtractorMock.Object,
			tokenBlacklistHelperMock.Object,
			loggerMock.Object,
			lbConfig);

		// Act
		var res = await svc.RefreshTokenAsync(existingRaw);

		// Assert
		res.Should().NotBeNull();
		res!.AccessToken.Should().Be("new.access");
		res.RefreshToken.Should().Be(newRaw);
		clientIpExtractorMock.Verify(c => c.GetClientIp(), Times.Once);
		refreshMock.Verify(r => r.RotateRefreshTokenAsync(existingRaw, "127.0.0.1"), Times.Once);
		userServiceMock.Verify(u => u.FindUserById(replacementRefresh.UserId), Times.Once);
	}

	[Fact]
	public async Task RefreshTokenAsync_RotateThrowsSecurityTokenException_ReturnsNullAndCallsClientIpExtractor()
	{
		// Arrange
		var existingRaw = "existing.raw";
		var userId = Guid.NewGuid();

		var userServiceMock = new Mock<IUserService>();
		var tokenServiceMock = new Mock<ITokenService>();

		var refreshMock = new Mock<IRefreshTokenService>();
		var existingRefresh = new RefreshToken
		{
			Id = 1,
			Token = "hashed-existing",
			UserId = userId,
			Username = "u",
			CreatedAt = DateTime.UtcNow,
			CreatedByIp = "127.0.0.1",
			ExpiresAt = DateTime.UtcNow.AddHours(1),
			Revoked = false
		};
		refreshMock.Setup(r => r.GetByTokenAsync(existingRaw)).ReturnsAsync(existingRefresh);
		refreshMock.Setup(r => r.RotateRefreshTokenAsync(existingRaw, "127.0.0.1"))
			.ThrowsAsync(new SecurityTokenException("invalid"));

		var tokenBlackListServiceMock = new Mock<ITokenBlackListService>();
		var clientIpExtractorMock = new Mock<IClientIpExtractor>();
		clientIpExtractorMock.Setup(c => c.GetClientIp()).Returns("127.0.0.1");
		var tokenBlacklistHelperMock = new Mock<ITokenBlacklistHelper>();

		var lbConfig = PrjAuth.Application.Tests.TestHelpers.TestHelpers.CreateLoadBalancedTokenConfiguration();
		var loggerMock = new Mock<ILogger<AuthService>>();

		var svc = new AuthService(
			tokenServiceMock.Object,
			userServiceMock.Object,
			refreshMock.Object,
			tokenBlackListServiceMock.Object,
			clientIpExtractorMock.Object,
			tokenBlacklistHelperMock.Object,
			loggerMock.Object,
			lbConfig);

		// Act
		var res = await svc.RefreshTokenAsync(existingRaw);

		// Assert
		res.Should().BeNull();
		clientIpExtractorMock.Verify(c => c.GetClientIp(), Times.Once);
		refreshMock.Verify(r => r.RotateRefreshTokenAsync(existingRaw, "127.0.0.1"), Times.Once);
	}

	[Fact]
	public async Task RefreshTokenAsync_WithMissingRefreshToken_ReturnsNull_AndDoesNotCallRotate()
	{
		// Arrange
		var missingRaw = "missing.raw";

		var userServiceMock = new Mock<IUserService>();
		var tokenServiceMock = new Mock<ITokenService>();
		var refreshMock = new Mock<IRefreshTokenService>();
		refreshMock.Setup(r => r.GetByTokenAsync(missingRaw)).ReturnsAsync((RefreshToken?)null);

		var tokenBlackListServiceMock = new Mock<ITokenBlackListService>();
		var clientIpExtractorMock = new Mock<IClientIpExtractor>();
		var tokenBlacklistHelperMock = new Mock<ITokenBlacklistHelper>();

		var lbConfig = PrjAuth.Application.Tests.TestHelpers.TestHelpers.CreateLoadBalancedTokenConfiguration();
		var loggerMock = new Mock<ILogger<AuthService>>();

		var svc = new AuthService(
			tokenServiceMock.Object,
			userServiceMock.Object,
			refreshMock.Object,
			tokenBlackListServiceMock.Object,
			clientIpExtractorMock.Object,
			tokenBlacklistHelperMock.Object,
			loggerMock.Object,
			lbConfig);

		// Act
		var res = await svc.RefreshTokenAsync(missingRaw);

		// Assert
		res.Should().BeNull();
		refreshMock.Verify(r => r.RotateRefreshTokenAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
		clientIpExtractorMock.Verify(c => c.GetClientIp(), Times.Never);
	}

	[Fact]
	public async Task RevokeTokenAsync_WithMissingRefreshToken_ReturnsFalse_AndDoesNotCallBlacklist()
	{
		// Arrange
		var missingRaw = "missing.raw";

		var tokenServiceMock = new Mock<ITokenService>();
		var userServiceMock = new Mock<IUserService>();
		var refreshMock = new Mock<IRefreshTokenService>();
		refreshMock.Setup(r => r.GetByTokenAsync(missingRaw)).ReturnsAsync((RefreshToken?)null);

		var tokenBlackListServiceMock = new Mock<ITokenBlackListService>();
		var clientIpExtractorMock = new Mock<IClientIpExtractor>();
		var tokenBlacklistHelperMock = new Mock<ITokenBlacklistHelper>();

		var lbConfig = PrjAuth.Application.Tests.TestHelpers.TestHelpers.CreateLoadBalancedTokenConfiguration();
		var loggerMock = new Mock<ILogger<AuthService>>();

		var svc = new AuthService(
			tokenServiceMock.Object,
			userServiceMock.Object,
			refreshMock.Object,
			tokenBlackListServiceMock.Object,
			clientIpExtractorMock.Object,
			tokenBlacklistHelperMock.Object,
			loggerMock.Object,
			lbConfig);

		// Act
		var result = await svc.RevokeTokenAsync(missingRaw);

		// Assert
		result.Should().BeFalse();
		clientIpExtractorMock.Verify(c => c.GetClientIp(), Times.Never);
		tokenBlacklistHelperMock.Verify(t => t.TryBlacklistCurrentAccessTokenAsync(), Times.Never);
	}
}
