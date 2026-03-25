using FluentAssertions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using PrjAuth.Application.Contracts.Implements;

namespace PrjAuth.Application.Tests;

public class TokenBlackListServiceTests
{
	private static IDistributedCache CreateDistributedCache() =>
			 new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));

	[Fact]
	public async Task IsTokenBlacklistedAsync_ReturnsFalse_ForMissingToken()
	{
		// Arrange
		var cache = CreateDistributedCache();
		var logger = new NullLogger<TokenBlackListService>();
		var svc = new TokenBlackListService(cache, logger);
		var randomJti = Guid.NewGuid().ToString();

		// Act
		var result = await svc.IsTokenBlacklistedAsync(randomJti);

		// Assert
		result.Should().BeFalse();
	}

	[Fact]
	public async Task BlacklistTokenAsync_Should_Persist_And_IsTokenBlacklistedAsync_ReturnsTrue()
	{
		// Arrange
		var cache = CreateDistributedCache();
		var logger = new NullLogger<TokenBlackListService>();
		var svc = new TokenBlackListService(cache, logger);
		var jti = Guid.NewGuid().ToString();
		var expiration = DateTime.UtcNow.AddMinutes(5);

		// Act
		await svc.BlacklistTokenAsync(jti, expiration);
		var result = await svc.IsTokenBlacklistedAsync(jti);

		// Assert
		result.Should().BeTrue();
	}
}
