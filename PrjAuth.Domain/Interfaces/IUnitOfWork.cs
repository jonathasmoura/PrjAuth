using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Domain.Interfaces
{
	public interface IUnitOfWork : IDisposable
	{

		IUserRepository Users { get; }

		Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
		Task BeginTransactionAsync(CancellationToken cancellationToken = default);
		Task CommitTransactionAsync(CancellationToken cancellationToken = default);
		Task RollbackTransactionAsync(CancellationToken cancellationToken = default);
	}
}
