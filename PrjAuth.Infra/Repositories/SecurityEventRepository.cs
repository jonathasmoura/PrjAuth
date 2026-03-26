using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;
using PrjAuth.Infra.DataContexts;
using System.Threading.Tasks;

namespace PrjAuth.Infra.Repositories
{
	public class SecurityEventRepository : ISecurityEventRepository
	{
		private readonly DbAuthContext _context;

		public SecurityEventRepository(DbAuthContext context)
		{
			_context = context;
		}

		public Task AddAsync(SecurityEvent securityEvent)
		{
			_context.Set<SecurityEvent>().Add(securityEvent);
			return Task.CompletedTask;
		}
	}
}
