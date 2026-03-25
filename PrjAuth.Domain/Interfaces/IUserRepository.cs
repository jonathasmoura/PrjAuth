using PrjAuth.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Domain.Interfaces
{
	public interface IUserRepository : IGenericRepository<User>
	{
		Task<User> GetByEmailAsync(string email);
	}
}
