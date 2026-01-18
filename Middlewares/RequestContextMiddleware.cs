using System.Security.Claims;

namespace WebApi.Middlewares
{
    public class RequestContextMiddleware
    {
        private const string CorrelationHeader = "X-Correlation-Id";
        private readonly RequestDelegate _next;

        public RequestContextMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            // 🔹 Correlation Id
            var correlationId = context.Request.Headers.ContainsKey(CorrelationHeader)
                ? context.Request.Headers[CorrelationHeader].ToString()
                : Guid.NewGuid().ToString();

            context.Items["CorrelationId"] = correlationId;
            context.Response.Headers[CorrelationHeader] = correlationId;

            // 🔹 JWT UserId
            context.Items["UserId"] =
                context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value
                ?? context.User?.FindFirst("user_id")?.Value;

            // 🔹 Client App Context
            context.Items["DeviceId"] = context.Request.Headers["X-Device-Id"].ToString();
            context.Items["AppId"] = context.Request.Headers["X-App-Id"].ToString();
            context.Items["Latitude"] = context.Request.Headers["X-Lattitude"].ToString();
            context.Items["Longitude"] = context.Request.Headers["X-Longitude"].ToString();

            // 🔹 IP Address
            context.Items["IpAddress"] =
                context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
                ?? context.Connection.RemoteIpAddress?.ToString();

            await _next(context);
        }
    }
}
