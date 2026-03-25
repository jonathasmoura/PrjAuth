using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PrjAuth.Api.Config;
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace PrjAuth.Api.Middlewares
{
	public class AuthRateLimitingMiddleware
	{
		private readonly RequestDelegate _next;
		private readonly IDistributedCache _cache;
		private readonly ILogger<AuthRateLimitingMiddleware> _logger;
		private readonly RateLimitingOptions _options;

		public AuthRateLimitingMiddleware(RequestDelegate next, IDistributedCache cache, IOptions<RateLimitingOptions> options, ILogger<AuthRateLimitingMiddleware> logger)
		{
			_next = next;
			_cache = cache;
			_logger = logger;
			_options = options.Value;
		}

		public async Task InvokeAsync(HttpContext context)
		{
			try
			{
				if (IsProtectedPath(context.Request.Path.Value, context.Request.Method))
				{
					var clientIp = GetClientIp(context);
					var path = context.Request.Path.Value?.ToLowerInvariant() ?? "unknown";
					var key = $"ratelimit:{path}:{clientIp}";

					var value = await _cache.GetStringAsync(key);
					int count = 0;
					if (!string.IsNullOrEmpty(value) && int.TryParse(value, out var parsed))
						count = parsed;

					if (count >= _options.MaxAttempts)
					{
						_logger.LogWarning("Rate limit excedido para IP {Ip} no caminho {Path}", clientIp, path);
						context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
						context.Response.Headers["Retry-After"] = _options.WindowSeconds.ToString();
						await context.Response.WriteAsync("Too many requests. Please try again later.");
						return;
					}

					count++;
					var cacheOptions = new DistributedCacheEntryOptions
					{
						AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.WindowSeconds)
					};

					await _cache.SetStringAsync(key, count.ToString(), cacheOptions);
				}
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Erro durante verificação de rate limiting - permitindo requisição");
			}

			await _next(context);
		}

		private bool IsProtectedPath(string? path, string method)
		{
			if (string.IsNullOrWhiteSpace(path)) return false;
			var p = path.ToLowerInvariant();

			foreach (var protectedPath in _options.ProtectedPaths ?? Enumerable.Empty<string>())
			{
				var normalized = protectedPath.ToLowerInvariant();
				if (p.StartsWith(normalized, StringComparison.OrdinalIgnoreCase))
				{
					if (method.Equals("POST", StringComparison.OrdinalIgnoreCase)) return true;
				}
			}
			return false;
		}

		private string GetClientIp(HttpContext context)
		{
			if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var values))
			{
				var first = values.FirstOrDefault();
				if (!string.IsNullOrEmpty(first))
				{
					var ip = first.Split(',').Select(x => x.Trim()).FirstOrDefault();
					if (IPAddress.TryParse(ip, out _)) return ip!;
				}
			}

			var remote = context.Connection.RemoteIpAddress;
			return remote?.ToString() ?? "unknown";
		}
	}
}
