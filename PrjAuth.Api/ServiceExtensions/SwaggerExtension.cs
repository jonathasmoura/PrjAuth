using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;

namespace PrjAuth.Api.ServiceExtensions
{
	public static class SwaggerExtension
	{
		public static IServiceCollection AddSwaggerWithJwt(this IServiceCollection services)
		{
			services.AddEndpointsApiExplorer();

			services.AddSwaggerGen(c =>
			{
				c.SwaggerDoc("v1", new OpenApiInfo
				{
					Version = "v1",
					Title = "ASP .NET 8 Web API",
					Description = "Authentication com Json Web Token"
				});

				var jwtSecurityScheme = new OpenApiSecurityScheme
				{
					Type = SecuritySchemeType.Http,
					Scheme = "bearer",
					BearerFormat = "JWT",
					Name = "Authorization",
					In = ParameterLocation.Header,
					Description = "Insira 'Bearer {token}' no campo Authorization",
					Reference = new OpenApiReference
					{
						Type = ReferenceType.SecurityScheme,
						Id = "Bearer"
					}
				};

				c.AddSecurityDefinition("Bearer", jwtSecurityScheme);
				c.AddSecurityRequirement(new OpenApiSecurityRequirement
				{
					{ jwtSecurityScheme, new string[] { } }
				});
			});

			return services;
		}
	}
}
