using System;

namespace PrjAuth.Domain.Entities.DomainBase
{
	public class EntityBase
	{
		public EntityBase()
		{
			Id = Guid.NewGuid();
			IsActive = true;
			Created = DateTime.UtcNow;
			ActivationDate = Created;
		}

		public Guid Id { get; set; }
		public bool IsActive { get; set; }
		public DateTime? ActivationDate { get; set; }
		public DateTime? InactivationDate { get; set; }
		public DateTime? UpdatedAt { get; set; }
		public DateTime Created { get; set; }
	}
}
