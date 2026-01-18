using Newtonsoft.Json;
using System.Diagnostics;
using System.Runtime.InteropServices;
using WebApi.Interface.Services.LogServiceInterfaces;
using WebApi.Models.LoggingModels;
using WebApis.Common;

namespace WebApi.Middlewares
{
    public static class HeaderExtensions
    {
        public static string ToJson(this IHeaderDictionary headers)
        {
            return JsonConvert.SerializeObject(headers.ToDictionary(h => h.Key, h => h.Value.ToString()));
        }
    }
    public class ExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IHostEnvironment _env;
        private readonly ILoggingService _errorLogger;
        public ExceptionMiddleware(RequestDelegate next, IHostEnvironment env , ILoggingService errorLogger)
        {
            _next = next;
            _env = env;
            _errorLogger = errorLogger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Skip Swagger
            if (context.Request.Path.StartsWithSegments("/swagger"))
            {
                await _next(context);
                return;
            }

            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context ,ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception ex)
        {
            try
            {
                var correlationId = context.Items["CorrelationId"]?.ToString() ?? context.TraceIdentifier;
                var userId = context.Items["UserId"]?.ToString();
                var endpoint = context.GetEndpoint();
                var actionDescriptor = endpoint?.Metadata.GetMetadata<Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor>();

                var controller = actionDescriptor?.ControllerName;
                var action = actionDescriptor?.ActionName;
                var ipaddress = context.Connection.RemoteIpAddress;
                var (errorCode, category, severity, httpStatus) =
                    ErrorCodeMapper.Map(ex);

                var errorLog = new ErrorLogModel
                {
                    UserId = userId,
                    Controller = controller,
                    Action = action,
                    EndPoint = context.Request.Path,
                    ErrorMessage = ex.Message,
                    ErrorCode = errorCode,
                    ErrorCategory = category,
                    HttpStatusCode = httpStatus,
                    ErrorStackTrace = ex.ToString(),
                    HttpMethod = context.Request.Method,
                    ApplicationVersion = RecieveAppInfo.Version,

                    CorrelationId = correlationId,
                    DeviceType = context.Items["DeviceType"]?.ToString(),
                    AppId = context.Items["AppId"]?.ToString(),
                    DeviceId = context.Items["DeviceId"]?.ToString(),
                    IpAddress = ipaddress?.ToString(),
                    Latitude = context.Items["Latitude"]?.ToString(),
                    Longitude = context.Items["Longitude"]?.ToString()
                };

                await _errorLogger.SaveErrorLogs(errorLog);
            }
            catch
            {
                // ❌ logging failure should never crash pipeline
            }

            if (!context.Response.HasStarted)
            {
                context.Response.Clear();
            }

            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/json";

            var response = ApiResponse<object>.Fail(
                message: "Something went wrong. Please try again later.",
                errorCode: "ERR_INTERNAL_SERVER"
            );

            await context.Response.WriteAsync(
                JsonConvert.SerializeObject(response));
        }

    }
}
