using Microsoft.AspNetCore.Http;
using PrjAuth.Application.Contracts.Interfaces;

namespace PrjAuth.Application.Contracts.Implements
{
	public class ClientIpExtractor : IClientIpExtractor
	{
		private readonly IHttpContextAccessor _httpContextAccessor;

		public ClientIpExtractor(IHttpContextAccessor httpContextAccessor)
		{
			_httpContextAccessor = httpContextAccessor;
		}

		public string GetClientIp()
		{
			var ctx = _httpContextAccessor?.HttpContext;
			if (ctx == null)
				return string.Empty;

			// Prioriza proxy/header X-Forwarded-For quando presente
			var forwarded = ctx.Request?.Headers["X-Forwarded-For"].FirstOrDefault();
			if (!string.IsNullOrWhiteSpace(forwarded))
				return forwarded;

			var remoteIp = ctx.Connection?.RemoteIpAddress?.ToString();
			return remoteIp ?? string.Empty;
		}
	}
}
