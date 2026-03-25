using System.Collections.Generic;

namespace PrjAuth.Api.Config
{
	public class RateLimitingOptions
	{
		public IEnumerable<string> ProtectedPaths { get; set; } = new[] { "/v1/users/login", "/v1/users/register", "/v1/users/refresh" };
		public int WindowSeconds { get; set; } = 60;
		public int MaxAttempts { get; set; } = 5;
	}
}
