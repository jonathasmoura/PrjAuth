using Microsoft.EntityFrameworkCore;
using PrjAuth.Domain.Entities;
using PrjAuth.Domain.Interfaces;
using PrjAuth.Infra.DataContexts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Infra.Repositories
{
	public class UserRepository : GenericRepository<User>, IUserRepository
	{
		public UserRepository(DbAuthContext dbAuthContext) : base(dbAuthContext)
		{
		}

		public async Task<User?> GetByEmailAsync(string email)
		{
			var user = await _dbAuthContext.Set<User>()
				.FirstOrDefaultAsync(u => u.Email == email);

			return user;
		}
	}
}
