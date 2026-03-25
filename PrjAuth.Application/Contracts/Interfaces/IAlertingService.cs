using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface IAlertingService
	{
		Task SendSecurityAlertAsync(string message);
	}
}
