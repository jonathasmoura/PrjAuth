using PrjAuth.Domain.Entities;
using System.Threading.Tasks;

namespace PrjAuth.Domain.Interfaces
{
	public interface ISecurityEventRepository
	{
		Task AddAsync(SecurityEvent securityEvent);
	}
}
