using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;
using PrjAuth.Infra.DataContexts;

namespace PrjAuth.Infra.Repositories
{
	public class SecurityEventRepository : ISecurityEventRepository
	{
		private readonly DbAuthContext _context;

		public SecurityEventRepository(DbAuthContext context)
		{
			_context = context;
		}

		public async Task SaveAsync(SecurityEvent securityEvent)
		{
			_context.Set<SecurityEvent>().Add(securityEvent);
			await _context.SaveChangesAsync().ConfigureAwait(false);
		}
	}
}
