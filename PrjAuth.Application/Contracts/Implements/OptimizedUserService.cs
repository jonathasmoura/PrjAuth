using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using PrjAuth.Application.Contracts.Interfaces;
using PrjAuth.Application.Dtos;
using PrjAuth.Domain.Interfaces;
using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace PrjAuth.Application.Contracts.Implements
{
	public class OptimizedUserService : IOptimizedUserService
	{
		private readonly IUserRepository _userRepository;
		private readonly IDistributedCache _distributedCache;
		private readonly IMemoryCache _memoryCache;
		private readonly ILogger<OptimizedUserService> _logger;
		private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);

		public OptimizedUserService(
			IUserRepository userRepository,
			IDistributedCache distributedCache,
			IMemoryCache memoryCache,
			ILogger<OptimizedUserService> logger)
		{
			_userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
			_distributedCache = distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
			_memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
			_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		}

		public async Task<UserDto?> GetByIdAsync(Guid id)
		{
			if (id == Guid.Empty) return null;

			var cacheKey = $"user:{id}";

			// 1) Fast path: memory cache
			if (_memoryCache.TryGetValue(cacheKey, out UserDto cachedUser))
			{
				return cachedUser;
			}

			// 2) Distributed cache (Redis) - deserializa se presente
			try
			{
				var cachedBytes = await _distributedCache.GetAsync(cacheKey).ConfigureAwait(false);
				if (cachedBytes != null && cachedBytes.Length > 0)
				{
					var json = Encoding.UTF8.GetString(cachedBytes);
					var dto = JsonSerializer.Deserialize<UserDto>(json);
					if (dto != null)
					{
						// popula cache local para leituras subsequentes rápidas
						_memoryCache.Set(cacheKey, dto, CacheTtl);
						return dto;
					}
				}
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao acessar cache distribuído para chave {CacheKey}. Continuando sem cache distribuído.", cacheKey);
				// fallback: continue para buscar no repositório
			}

			// 3) Cache miss: buscar no repositório
			var user = await _userRepository.GetByIdAsync(id);
			if (user == null) return null;

			var userDto = new UserDto
			{
				Id = user.Id,
				Username = user.Name,
				Email = user.Email,
				Roles = user.Roles?.ToArray() ?? Array.Empty<string>()
			};

			// 4) Popula ambos caches (memory + distributed) de forma resiliente
			try
			{
				_memoryCache.Set(cacheKey, userDto, CacheTtl);

				var json = JsonSerializer.Serialize(userDto);
				var bytes = Encoding.UTF8.GetBytes(json);
				var options = new DistributedCacheEntryOptions
				{
					AbsoluteExpirationRelativeToNow = CacheTtl
				};
				await _distributedCache.SetAsync(cacheKey, bytes, options).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Falha ao popular cache para chave {CacheKey}. Cache local já populado.", cacheKey);
			}

			return userDto;
		}
	}
}
