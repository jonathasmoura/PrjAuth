using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using PrjAuth.Api.Controllers;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using System.Security.Claims;

namespace Prj.Api.Tests;

public class AuthControllerTests
{
	[Fact]
	public async Task Login_WithValidCredentials_SetsRefreshCookieAndReturnsTokens()
	{
		// Arrange
		var loginDto = new LoginUserDto { Email = "u@e.com", Password = "Pass123!" };
		var authServiceMock = new Mock<IAuthService>();
		var userServiceMock = new Mock<IUserService>();
		var tokenServiceMock = new Mock<ITokenService>();
		var blackListMock = new Mock<ITokenBlackListService>();
		var loggerMock = new Mock<ILogger<AuthController>>();

		var authResponse = new AuthResponseDto
		{
			AccessToken = "access.token",
			RefreshToken = "refresh.raw",
			ExpiresAt = DateTime.UtcNow.AddMinutes(30),
			User = new UserDto { Id = Guid.NewGuid(), Username = "u", Email = "u@e.com", Roles = Array.Empty<string>() }
		};

		authServiceMock.Setup(x => x.AuthenticateAsync(It.IsAny<LoginUserDto>())).ReturnsAsync(authResponse);

		var controller = new AuthController(authServiceMock.Object, userServiceMock.Object, loggerMock.Object, tokenServiceMock.Object, blackListMock.Object);
		controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

		// Act
		var result = await controller.Login(loginDto) as OkObjectResult;

		// Assert
		result.Should().NotBeNull();

		
		var value = result!.Value;
		value.Should().NotBeNull();

		var type = value.GetType();
		var prop = type.GetProperty("accessToken") ?? type.GetProperty("AccessToken");
		prop.Should().NotBeNull("retorno deve expor um token de acesso (accessToken ou AccessToken)");

		var accessToken = prop!.GetValue(value) as string;
		accessToken.Should().NotBeNullOrWhiteSpace();

		
		var setCookie = controller.Response.Headers["Set-Cookie"].FirstOrDefault();
		setCookie.Should().NotBeNull();
		setCookie.Should().Contain("refreshToken=");
	}

	[Fact]
	public async Task Logout_WithAuthorizationHeader_RevokesRefreshAndBlacklistsAccessToken()
	{
		// Arrange
		var authServiceMock = new Mock<IAuthService>();
		var userServiceMock = new Mock<IUserService>();
		var tokenServiceMock = new Mock<ITokenService>();
		var blackListMock = new Mock<ITokenBlackListService>();
		var loggerMock = new Mock<ILogger<AuthController>>();

		var controller = new AuthController(authServiceMock.Object, userServiceMock.Object, loggerMock.Object, tokenServiceMock.Object, blackListMock.Object);
		var ctx = new DefaultHttpContext();
		
		ctx.Request.Headers["Cookie"] = "refreshToken=refresh.raw";
		ctx.Request.Headers["Authorization"] = "Bearer header.token";
		controller.ControllerContext = new ControllerContext { HttpContext = ctx };
		
		tokenServiceMock.Setup(x => x.GetJti(It.IsAny<string>())).Returns((string?)null);

		// Act
		var result = await controller.Logout(null) as OkObjectResult;

		// Assert
		result.Should().NotBeNull();
		authServiceMock.Verify(a => a.RevokeTokenAsync(It.IsAny<string>()), Times.AtLeastOnce);
		
		controller.Response.Headers["Set-Cookie"].ToString().Should().Contain("refreshToken=;"); // header de deleção do cookie
	}

	[Fact]
	public async Task Logout_WhenAccessTokenContainsJti_BlacklistsThatJti()
	{
		// Arrange
		var authServiceMock = new Mock<IAuthService>();
		var userServiceMock = new Mock<IUserService>();
		var tokenServiceMock = new Mock<ITokenService>();
		var blackListMock = new Mock<ITokenBlackListService>();
		var loggerMock = new Mock<ILogger<AuthController>>();

		var controller = new AuthController(authServiceMock.Object, userServiceMock.Object, loggerMock.Object, tokenServiceMock.Object, blackListMock.Object);
		var ctx = new DefaultHttpContext();

		// Simula cookie e header Authorization
		ctx.Request.Headers["Cookie"] = "refreshToken=refresh.raw";
		ctx.Request.Headers["Authorization"] = "Bearer header.token";
		controller.ControllerContext = new ControllerContext { HttpContext = ctx };

		
		var jti = Guid.NewGuid().ToString();
		var expDate = DateTime.UtcNow.AddMinutes(10);
		var expSeconds = new DateTimeOffset(expDate).ToUnixTimeSeconds();
		var claims = new[]
		{
				new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, jti),
				new Claim("exp", expSeconds.ToString())
			};
		var principal = new ClaimsPrincipal(new ClaimsIdentity(claims));

		
		var expectedExpiration = DateTimeOffset.FromUnixTimeSeconds(expSeconds).UtcDateTime;
		tokenServiceMock.Setup(x => x.GetJti(It.IsAny<string>())).Returns(jti);
		tokenServiceMock.Setup(x => x.GetTokenExpirationUtc(It.IsAny<string>())).Returns(expectedExpiration);

		blackListMock.Setup(b => b.BlacklistTokenAsync(jti, It.IsAny<DateTime>())).Returns(Task.CompletedTask).Verifiable();

		// Act
		var result = await controller.Logout(null) as OkObjectResult;

		// Assert
		result.Should().NotBeNull();
		authServiceMock.Verify(a => a.RevokeTokenAsync(It.IsAny<string>()), Times.AtLeastOnce);

		blackListMock.Verify(b => b.BlacklistTokenAsync(jti, expectedExpiration), Times.Once);

		controller.Response.Headers["Set-Cookie"].ToString().Should().Contain("refreshToken=;");
	}
}
