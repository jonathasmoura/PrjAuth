using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace PrjAuth.Api.Middlewares
{
	public class ExceptionHandlingMiddleware
	{
		private readonly RequestDelegate _next;
		private readonly ILogger<ExceptionHandlingMiddleware> _logger;

		public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
		{
			_next = next;
			_logger = logger;
		}

		public async Task InvokeAsync(HttpContext httpContext)
		{
			try
			{
				await _next(httpContext);
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Unhandled exception");
				httpContext.Response.ContentType = "application/json";
				httpContext.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

				var problem = new
				{
					title = "An error occurred while processing your request.",
					detail = ex.Message
				};

				await httpContext.Response.WriteAsync(JsonSerializer.Serialize(problem));
			}
		}
	}
}
