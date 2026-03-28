using System.Collections.Generic;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using PrjAuth.Application.Configuration;

namespace PrjAuth.Application.Tests.TestHelpers
{
	public static class TestHelpers
	{
		public static IConfiguration CreateConfiguration(Dictionary<string, string?>? settings = null)
		{
			var inMemorySettings = settings ?? new Dictionary<string, string?>
			{
				{ "Jwt:AccessTokenExpirationMinutes", "30" },
				{ "Jwt:Issuer", "test-issuer" },
				{ "Jwt:Audience", "test-audience" },
				{ "Jwt:Key", "test-key" }
			};

			return new ConfigurationBuilder().AddInMemoryCollection(inMemorySettings).Build();
		}

		public static IDistributedCache CreateDistributedCache()
		{
			return new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
		}

		public static LoadBalancedTokenConfiguration CreateLoadBalancedTokenConfiguration(Dictionary<string, string?>? settings = null)
		{
			var configuration = CreateConfiguration(settings);
			var cache = CreateDistributedCache();
			var logger = new Mock<ILogger<LoadBalancedTokenConfiguration>>().Object;
			return new LoadBalancedTokenConfiguration(configuration, cache, logger);
		}
	}
}
