using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace BookwormsOnline.Controllers
{
    public class ErrorController : Controller
    {
        private readonly ILogger<ErrorController> _logger;

        public ErrorController(ILogger<ErrorController> logger)
        {
            _logger = logger;
        }

        // Handle HTTP status codes (e.g., 404, 403)
        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            switch (statusCode)
            {
                case 404:
                    _logger.LogWarning("404 Not Found: {Path}", HttpContext.Request.Path.Replace(Environment.NewLine, "").Replace("\n", "").Replace("\r", ""));
                    return View("NotFound");
                case 403:
                    _logger.LogWarning("403 Forbidden: {Path}", HttpContext.Request.Path.Replace(Environment.NewLine, "").Replace("\n", "").Replace("\r", ""));
                    return View("Forbidden");
                default:
                    _logger.LogWarning("Unexpected status code: {StatusCode}", statusCode);
                    return View("Error");
            }
        }

        // Handle unhandled exceptions (500 errors)
        [Route("Error/500")]
        public IActionResult ServerError()
        {
            _logger.LogError("500 Internal Server Error: {Path}", HttpContext.Request.Path.Replace(Environment.NewLine, "").Replace("\n", "").Replace("\r", ""));
            return View("Error");
        }

        // Custom 404 page for unmatched routes
        public IActionResult NotFound()
        {
            Response.StatusCode = 404;
            return View("NotFound");
        }

        [Route("Error/403")]
        public IActionResult Forbidden()
        {
            return View("Forbidden");
        }
    }
}