using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Implements
{
	public class AlertingService : IAlertingService
	{
		private readonly ILogger<AlertingService> _logger;
		public AlertingService(ILogger<AlertingService> logger) { _logger = logger; }

		public Task SendSecurityAlertAsync(string message)
		{
			_logger.LogWarning("Security alert: {Message}", message);
			return Task.CompletedTask;
		}
	}
}
