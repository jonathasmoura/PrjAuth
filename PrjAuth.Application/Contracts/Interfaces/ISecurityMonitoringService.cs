using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface ISecurityMonitoringService
	{
		Task LogSecurityEventAsync(string eventType, string details, string? userId = null);
	}
}
