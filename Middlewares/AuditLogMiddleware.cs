using WebApi.Interface.Repositories.Log;
using WebApi.Interface.Services.LogServiceInterfaces;
using WebApi.Models.LoggingModels;

public class AuditLogMiddleware
{
    private readonly RequestDelegate _next;

    public AuditLogMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, ILoggingService logService)
    {
        await _next(context); // request complete hone do

        try
        {
            var correlationId = context.Items["CorrelationId"]?.ToString() ?? context.TraceIdentifier;
            var userId = context.Items["UserId"]?.ToString();
            var endpoint = context.GetEndpoint();
            var actionDescriptor = endpoint?.Metadata.GetMetadata<Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor>();

            var controller = actionDescriptor?.ControllerName;
            var action = actionDescriptor?.ActionName;
            var statusCode = context.Response.StatusCode;
           
            var auditRequest = new AuditLogModel
            {
                UserId = context.Items["UserId"]?.ToString(),
                AppId = context.Items["AppId"]?.ToString(),
                ControllerName = controller,
                ActionName = action,
                EndPoint = context.Request.Path,
                HttpMethod = context.Request.Method,
                HttpStatusCode = statusCode,
                EventStatus = context.Response.StatusCode >= 400 ? "FAILED" : "SUCCESS",
                CorrelationId = correlationId,
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                DeviceType = context.Items["DeviceType"]?.ToString(),
                DeviceId = context.Items["DeviceId"]?.ToString(),
                UserAgent = context.Request.Headers["User-Agent"].ToString(),
                ApplicationVersion = context.Items["AppVersion"]?.ToString(),
                Latitude = context.Items["Latitude"]?.ToString(),
                Longitude = context.Items["Longitude"]?.ToString()
            };
            // Fire & forget, performance safe
            _ = Task.Run(() => logService.SaveAuditLogs(auditRequest));
        }
        catch (Exception ex)
        {

        }
    }
}
