using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Implements
{
	public class SecurityMonitoringService : ISecurityMonitoringService
	{
		private readonly ISecurityEventRepository _securityEventRepository;
		private readonly IAlertingService _alertingService;
		private readonly IHttpContextAccessor _httpContextAccessor;
		private readonly ILogger<SecurityMonitoringService> _logger;
		private readonly IUnitOfWork _unitOfWork;

		public SecurityMonitoringService(
			ISecurityEventRepository securityEventRepository,
			IAlertingService alertingService,
			IHttpContextAccessor httpContextAccessor,
			ILogger<SecurityMonitoringService> logger,
			IUnitOfWork unitOfWork)
		{
			_securityEventRepository = securityEventRepository ?? throw new ArgumentNullException(nameof(securityEventRepository));
			_alertingService = alertingService ?? throw new ArgumentNullException(nameof(alertingService));
			_httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
			_unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
		}

		public async Task LogSecurityEventAsync(string eventType, string details, string? userId = null)
		{
			try
			{
				var ctx = _httpContextAccessor.HttpContext;
				var ip = GetClientIp(ctx);
				var userAgent = ctx?.Request?.Headers["User-Agent"].FirstOrDefault();
				var traceId = ctx?.TraceIdentifier;

				var securityEvent = new SecurityEvent
				{
					EventType = eventType,
					Details = details,
					UserId = userId,
					Timestamp = DateTime.UtcNow,
					IpAddress = ip,
					UserAgent = userAgent
				};

				await _securityEventRepository.AddAsync(securityEvent).ConfigureAwait(false);

				await _unitOfWork.SaveChangesAsync().ConfigureAwait(false);

				_logger.LogInformation("Security event {EventType} recorded for user {UserId} ip {Ip} trace {TraceId}",
					eventType, userId ?? "<anonymous>", ip ?? "<unknown>", traceId ?? "<none>");

				if (string.Equals(eventType, "MULTIPLE_FAILED_LOGINS", StringComparison.OrdinalIgnoreCase))
				{
					await _alertingService.SendSecurityAlertAsync(
						$"Multiple failed login attempts for user {userId ?? "<unknown>"} from {ip ?? "<unknown>"}").ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Failed to log security event {EventType} for user {UserId}", eventType, userId);
			}
		}

		private static string? GetClientIp(HttpContext? context)
		{
			if (context == null) return null;

			if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var xff) && !string.IsNullOrWhiteSpace(xff.FirstOrDefault()))
			{
				var ips = xff.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries);
				if (ips.Length > 0) return ips[0].Trim();
			}

			return context.Connection?.RemoteIpAddress?.ToString();
		}
	}
}
