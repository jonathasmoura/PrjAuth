using Microsoft.EntityFrameworkCore.Storage;
using PrjAuth.Domain.Interfaces;
using PrjAuth.Infra.DataContexts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Infra.Repositories
{
	public class UnitOfWork : IUnitOfWork
	{
		private readonly DbAuthContext _context;
		private IDbContextTransaction? _currentTransaction;

		public IUserRepository Users { get; }

		public UnitOfWork(DbAuthContext context, IUserRepository users)
		{
			_context = context;
			Users = users;
		}

		public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) =>
			_context.SaveChangesAsync(cancellationToken);

		public async Task BeginTransactionAsync(CancellationToken cancellationToken = default)
		{
			if (_currentTransaction != null) return;
			_currentTransaction = await _context.Database.BeginTransactionAsync(cancellationToken);
		}

		public async Task CommitTransactionAsync(CancellationToken cancellationToken = default)
		{
			if (_currentTransaction == null) return;
			await _context.SaveChangesAsync(cancellationToken);
			await _currentTransaction.CommitAsync(cancellationToken);
			await _currentTransaction.DisposeAsync();
			_currentTransaction = null;
		}

		public async Task RollbackTransactionAsync(CancellationToken cancellationToken = default)
		{
			if (_currentTransaction == null) return;
			await _currentTransaction.RollbackAsync(cancellationToken);
			await _currentTransaction.DisposeAsync();
			_currentTransaction = null;
		}

		public void Dispose()
		{
			_currentTransaction?.Dispose();
			_currentTransaction = null;
		}
	}
}
