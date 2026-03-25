using PrjAuth.Application.Dtos;
using PrjAuth.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Interfaces
{
	public interface IOptimizedUserService
	{
		Task<UserDto?> GetByIdAsync(Guid id);
	}
}
