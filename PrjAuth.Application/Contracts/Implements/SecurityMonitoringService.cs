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

		public SecurityMonitoringService(
			ISecurityEventRepository securityEventRepository,
			IAlertingService alertingService,
			IHttpContextAccessor httpContextAccessor,
			ILogger<SecurityMonitoringService> logger)
		{
			_securityEventRepository = securityEventRepository ?? throw new ArgumentNullException(nameof(securityEventRepository));
			_alertingService = alertingService ?? throw new ArgumentNullException(nameof(alertingService));
			_httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
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

				// Persistir evento (assíncrono)
				await _securityEventRepository.SaveAsync(securityEvent).ConfigureAwait(false);

				// Logging estruturado (não logar PII sensível)
				_logger.LogInformation("Security event {EventType} recorded for user {UserId} ip {Ip} trace {TraceId}",
					eventType, userId ?? "<anonymous>", ip ?? "<unknown>", traceId ?? "<none>");

				// Alertas: policy-driven, assíncrono
				if (string.Equals(eventType, "MULTIPLE_FAILED_LOGINS", StringComparison.OrdinalIgnoreCase))
				{
					// Não bloquear o fluxo principal — enviar alerta de forma resiliente
					await _alertingService.SendSecurityAlertAsync(
						$"Multiple failed login attempts for user {userId ?? "<unknown>"} from {ip ?? "<unknown>"}").ConfigureAwait(false);
				}
			}
			catch (Exception ex)
			{
				// Trata falhas no monitoramento sem propagar (defesa em profundidade)
				_logger.LogError(ex, "Failed to log security event {EventType} for user {UserId}", eventType, userId);
			}
		}

		private static string? GetClientIp(HttpContext? context)
		{
			if (context == null) return null;

			// Respeitar X-Forwarded-For quando atrás de load balancer / proxy
			if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var xff) && !string.IsNullOrWhiteSpace(xff.FirstOrDefault()))
			{
				var ips = xff.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries);
				if (ips.Length > 0) return ips[0].Trim();
			}

			return context.Connection?.RemoteIpAddress?.ToString();
		}
	}
}
