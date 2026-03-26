using Microsoft.EntityFrameworkCore;
using PrjAuth.Domain.Entities.DomainBase;
using PrjAuth.Domain.Interfaces;
using PrjAuth.Infra.DataContexts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Infra.Repositories
{
	public abstract class GenericRepository<T> : IGenericRepository<T> where T : EntityBase
	{
		protected readonly DbAuthContext _dbAuthContext;

		protected GenericRepository(DbAuthContext dbAuthContext)
		{
			_dbAuthContext = dbAuthContext;
		}

		public async Task<IEnumerable<T>> GetAllAsync()
		{
			return await _dbAuthContext.Set<T>().ToListAsync();
		}

		public async Task<T?> GetByIdAsync(Guid id)
		{
			var entity = await _dbAuthContext.Set<T>().FindAsync(id);
			return entity;
		}

		public async Task AddAsync(T entity)
		{
			await _dbAuthContext.Set<T>().AddAsync(entity);
		}

		public Task UpdateAsync(T entity)
		{
			_dbAuthContext.Set<T>().Update(entity);
			return Task.CompletedTask;
		}

		public Task DeleteAsync(T entity)
		{
			_dbAuthContext.Set<T>().Remove(entity);
			return Task.CompletedTask;
		}
	}
}
