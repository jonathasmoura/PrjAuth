using PrjAuth.Domain.Entities.DomainBase;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Domain.Interfaces
{
	public interface IGenericRepository<T> where T : EntityBase
	{
		Task<T?> GetByIdAsync(Guid id);
		Task<IEnumerable<T>> GetAllAsync();
		Task AddAsync(T entity);
		Task DeleteAsync(T entity);
		Task UpdateAsync(T entity);        
	}
}
