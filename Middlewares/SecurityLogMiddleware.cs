namespace WebApi.Middlewares
{
    using System.Net;
    using Microsoft.AspNetCore.Http;
    using WebApi.Interface.Services.LogServiceInterfaces;
    using WebApi.Models.LoggingModels;

    public class SecurityLogMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityLogMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        //public async Task InvokeAsync(HttpContext context, ISecurityLogService securityLogService)
        //{
        //    // Fire & forget security logging
        //    context.Response.OnCompleted(async () =>
        //    {
        //        try
        //        {
        //            var statusCode = context.Response.StatusCode;

        //            // 🔹 Security events only
        //            bool isSecurityEvent = statusCode == 401 || statusCode == 403;
        //            var jwtTampered = context.Items["JWT_INVALID"] as bool? ?? false;
        //            var rateLimitHit = context.Items["RATE_LIMIT_HIT"] as bool? ?? false;

        //            if (!isSecurityEvent && !jwtTampered && !rateLimitHit)
        //                return;

        //            var ip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
        //                     ?? context.Connection.RemoteIpAddress?.ToString();

        //            // Geo lookup (dummy for example)
        //            var (country, state, latitude, longitude) = GeoIpService.Lookup(ip);

        //            var log = new SecurityLogModel
        //            {
        //                EventType = jwtTampered ? "TOKEN_INVALID" :
        //                           rateLimitHit ? "RATE_LIMIT" :
        //                           "LOGIN_FAILED",
        //                Severity = "HIGH",
        //                UserId = context.Items["UserId"]?.ToString(),
        //                AppId = context.Items["AppId"]?.ToString(),
        //                DeviceId = context.Items["DeviceId"]?.ToString(),
        //                UserAgent = context.Request.Headers["User-Agent"].ToString(),
        //                IpAddress = ip,
        //                ForwardedIp = context.Request.Headers["X-Forwarded-For"].ToString(),
        //                Country = country,
        //                State = state,
        //                Latitude = latitude,
        //                Longitude = longitude,
        //                EndPoint = context.Request.Path,
        //                HttpMethod = context.Request.Method,
        //                HttpStatus = statusCode,
        //                CorrelationId = context.Items["CorrelationId"]?.ToString() ?? context.TraceIdentifier,
        //                Reason = "Security event detected"
        //            };

        //            await securityLogService.SaveSecurityLogAsync(log);
        //        }
        //        catch
        //        {
        //            // ❌ Fail safe, never crash request
        //        }
        //    });

        //    await _next(context);
        //}
    }

}
