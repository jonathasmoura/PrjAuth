using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using PrjAuth.Application.Contracts.Implements;
using PrjAuth.Application.Contracts.Interfaces;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Tests.Security
{
	public class SecurityHardenedTokenValidatorTests
	{
		[Fact]
		public async Task ValidateTokenAsync_WhenTokenIsNullOrWhitespace_ReturnsNull()
		{
			// Arrange
			var tokenServiceMock = new Mock<ITokenService>();
			var blackListMock = new Mock<ITokenBlackListService>();
			var validator = new SecurityHardenedTokenValidator(tokenServiceMock.Object, blackListMock.Object, new NullLogger<SecurityHardenedTokenValidator>());

			// Act
			var res1 = await validator.ValidateTokenAsync(null!);
			var res2 = await validator.ValidateTokenAsync(string.Empty);
			var res3 = await validator.ValidateTokenAsync("   ");

			// Assert
			res1.Should().BeNull();
			res2.Should().BeNull();
			res3.Should().BeNull();
		}

		[Fact]
		public async Task ValidateTokenAsync_WhenPrincipalHasNoJti_DoesNotCallBlacklist_ReturnsPrincipal()
		{
			// Arrange
			var token = "dummy";
			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, "user") }));

			var tokenServiceMock = new Mock<ITokenService>();
			// Ajuste: passar explicitamente o segundo argumento no setup do mock para evitar expression-tree com optional args
			tokenServiceMock.Setup(x => x.ValidateToken(token, It.IsAny<bool>())).Returns(principal);

			var blackListMock = new Mock<ITokenBlackListService>();

			var validator = new SecurityHardenedTokenValidator(tokenServiceMock.Object, blackListMock.Object, new NullLogger<SecurityHardenedTokenValidator>());

			// Act
			var res = await validator.ValidateTokenAsync(token);

			// Assert
			res.Should().NotBeNull();
			blackListMock.Verify(x => x.IsTokenBlacklistedAsync(It.IsAny<string>()), Times.Never);
		}
		[Fact]
		public async Task ValidateTokenAsync_WhenTokenIsBlacklisted_ReturnsNull()
		{
			// Arrange
			var token = "dummy";
			var jti = Guid.NewGuid().ToString();
			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(JwtRegisteredClaimNames.Jti, jti) }));

			var tokenServiceMock = new Mock<ITokenService>();
			tokenServiceMock.Setup(x => x.ValidateToken(token, It.IsAny<bool>())).Returns(principal);

			var blackListMock = new Mock<ITokenBlackListService>();
			blackListMock.Setup(x => x.IsTokenBlacklistedAsync(jti)).ReturnsAsync(true);

			var validator = new SecurityHardenedTokenValidator(tokenServiceMock.Object, blackListMock.Object, new NullLogger<SecurityHardenedTokenValidator>());

			// Act
			var res = await validator.ValidateTokenAsync(token);

			// Assert
			res.Should().BeNull();
		}

		[Fact]
		public async Task ValidateTokenAsync_WhenNotBlacklisted_ReturnsPrincipal()
		{
			// Arrange
			var token = "dummy";
			var jti = Guid.NewGuid().ToString();
			var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(JwtRegisteredClaimNames.Jti, jti) }));

			var tokenServiceMock = new Mock<ITokenService>();
			tokenServiceMock.Setup(x => x.ValidateToken(token, It.IsAny<bool>())).Returns(principal);

			var blackListMock = new Mock<ITokenBlackListService>();
			blackListMock.Setup(x => x.IsTokenBlacklistedAsync(jti)).ReturnsAsync(false);

			var validator = new SecurityHardenedTokenValidator(tokenServiceMock.Object, blackListMock.Object, new NullLogger<SecurityHardenedTokenValidator>());

			// Act
			var res = await validator.ValidateTokenAsync(token);

			// Assert
			res.Should().NotBeNull();
			res!.FindFirst(JwtRegisteredClaimNames.Jti)!.Value.Should().Be(jti);
		}
	}
}
