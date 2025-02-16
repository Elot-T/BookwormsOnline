using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using BookwormsOnline.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.Threading.Tasks;
using System;
using MimeKit;
using MailKit.Net.Smtp;
using Ganss.Xss;
using System.Linq;
using Newtonsoft.Json;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Filters;

namespace BookwormsOnline.Controllers
{
    public class UsersController : Controller
    {
        private readonly MyDbContext _context;
        private readonly PasswordHasher<User> _passwordHasher;
        private readonly ILogger<UsersController> _logger;
        private readonly IEmailSender _emailSender;
        private readonly string _recaptchaSecretKey = "6LdNZbYqAAAAAALz3xuy7vf2JVW4-GUMzksxIOSk"; // Your secret key

        public UsersController(MyDbContext context, ILogger<UsersController> logger, IEmailSender emailSender)
        {
            _context = context;
            _passwordHasher = new PasswordHasher<User>();
            _logger = logger;
            _emailSender = emailSender; // Assign the injected IEmailSender
        }

        // Register GET method
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        // Register POST method with password hashing and reCAPTCHA v3
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(User model, string gRecaptchaResponse, IFormFile UploadedFile)
        {
            try
            {
                var sanitizer = new HtmlSanitizer();
                model.FirstName = sanitizer.Sanitize(model.FirstName);
                model.LastName = sanitizer.Sanitize(model.LastName);
                model.BillingAddress = sanitizer.Sanitize(model.BillingAddress);
                model.ShippingAddress = sanitizer.Sanitize(model.ShippingAddress);

                if (ModelState.IsValid)
                {
                    _logger.LogInformation("Model is valid, starting reCAPTCHA validation.");

                    // Verify reCAPTCHA token using v3
                    var isValidRecaptcha = await VerifyRecaptchaAsync(gRecaptchaResponse);
                    if (!isValidRecaptcha.Item1)
                    {
                    
                        ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                        return View(model);
                    }
                    _logger.LogInformation("reCAPTCHA verification succeeded.");

                    // Check if email already exists
                    bool emailExists = _context.Users.Any(u => u.Email == model.Email);
                    if (emailExists)
                    {
                       
                        ModelState.AddModelError("Email", "Email is already registered.");
                        return View(model);
                    }
                  

                    // Hash the user's password before saving it to the database
                    var hashedPassword = _passwordHasher.HashPassword(model, model.Password);
                    model.Password = hashedPassword; // Replace the plain password with the hashed one
                    model.CreditCardNo = EncryptionHelper.Encrypt(model.CreditCardNo);

                    _logger.LogInformation("Password hashed successfully.");
                    model.PasswordLastChanged = DateTime.UtcNow;

                    if (ModelState.IsValid)
                    {
                        if (UploadedFile != null && UploadedFile.Length > 0)
                        {
                            using (var memoryStream = new MemoryStream())
                            {
                                await UploadedFile.CopyToAsync(memoryStream);
                                model.UploadedFile = memoryStream.ToArray(); // Store the file as a byte array
                            }
                        }
                        else
                        {
                            ModelState.AddModelError("UploadedFile", "File is required.");
                            return View(model);
                        }


                        // Add the user to the database
                        _context.Users.Add(model);
                        await _context.SaveChangesAsync();
                       

                        TempData["SuccessMessage"] = "Registration successful!";
                        return RedirectToAction("Login");
                    }
                    else
                    {
                        _logger.LogWarning("Model validation failed. Errors:");
                        foreach (var error in ModelState.Values.SelectMany(v => v.Errors))
                        {
                            _logger.LogWarning("Validation Error: {0}", error.ErrorMessage);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
              
                ModelState.AddModelError("", "An error occurred. Please try again.");
            }

            return View(model);
        }

        // Login GET method
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        // Login POST method
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string email, string password)
        {
            var sanitizedEmail = email?.Trim().ToLower();
            if (string.IsNullOrEmpty(sanitizedEmail) || !IsValidEmail(sanitizedEmail))
            {
                ModelState.AddModelError("email", "Please enter a valid email address.");
               
                return View();
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == sanitizedEmail);
            if (user == null)
            {
               
                ModelState.AddModelError("", "Invalid email or password.");
                return View();
            }

            if (user.PasswordLastChanged.AddDays(30) < DateTime.UtcNow)
            {
             
                TempData["ErrorMessage"] = "Your password has expired. Please reset your password.";
                return RedirectToAction("ForgotPassword", "Users");
            }

            var passwordVerificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, password);
            if (passwordVerificationResult == PasswordVerificationResult.Success)
            {
                // Log successful authentication attempt
              
                await InvalidateUserSessions(user.Id);

                var newSession = new UserSession
                {
                    UserId = user.Id,
                    SessionId = Guid.NewGuid().ToString(),
                    DeviceInfo = Request.Headers["User-Agent"].ToString(),
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    LoginTime = DateTime.UtcNow,
                    LastActivityTime = DateTime.UtcNow,
                    SessionExpiryTime = DateTime.UtcNow.AddMinutes(1), // 1 minute for testing
                    IsActive = true
                };

                _logger.LogInformation($"New session created for {user.Email} - Expires at {newSession.SessionExpiryTime}");

                // Store session ID in cookie
                Response.Cookies.Append("SessionToken", newSession.SessionId, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = newSession.SessionExpiryTime
                });

                // Check for existing active sessions
                var activeSessions = await _context.UserSessions
                    .Where(s => s.UserId == user.Id && s.IsActive)
                    .ToListAsync();

                if (activeSessions.Any())
                {
                  

                    TempData["WarningMessage"] = $"Active sessions detected on {activeSessions.Count} devices.";

                    // Uncomment to enforce single-session login
                 
                    foreach (var session in activeSessions) session.IsActive = false;
                }

                _context.UserSessions.Add(newSession);
                await _context.SaveChangesAsync();

                // Store session identifiers
                HttpContext.Session.SetString("UserId", user.Id.ToString());
                HttpContext.Session.SetString("UserName", user.FirstName);
                HttpContext.Session.SetString("CurrentSessionId", newSession.SessionId);

            

                TempData["SuccessMessage"] = "Login successful!";
                return RedirectToAction("Dashboard", "Users");
            }

            
            ModelState.AddModelError("", "Invalid email or password.");
            return View();
        }

        public async Task InvalidateUserSessions(Guid userId)
        {
            var activeSessions = await _context.UserSessions
                .Where(s => s.UserId == userId && s.IsActive)
                .ToListAsync();

            foreach (var session in activeSessions)
            {
                session.IsActive = false;
            }

            await _context.SaveChangesAsync();
        }

        [HttpGet]
        public async Task<IActionResult> CheckSession()
        {
            var sessionToken = Request.Cookies["SessionToken"];
           

            if (string.IsNullOrEmpty(sessionToken))
            {
                _logger.LogWarning("No active session token found - Forcing logout");

                // Clear any residual session data
                HttpContext.Session.Clear();
                Response.Cookies.Delete("SessionToken");

                return Json(new
                {
                    isActive = false,
                    forceLogout = true,  // New flag
                    message = "Session expired. Please login again."
                });
            }


            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.SessionId == sessionToken);

            if (session == null)
            {
             
                return Json(new { isActive = false, message = "Invalid session" });
            }

            // Log session details
            _logger.LogInformation($"Session Status - Active: {session.IsActive}, Expires: {session.SessionExpiryTime}, Last Active: {session.LastActivityTime}");

            // Check for manual deactivation
            if (!session.IsActive)
            {
                
                return Json(new { isActive = false, message = "Session terminated" });
            }

            // Check absolute expiry
            if (DateTime.UtcNow > session.SessionExpiryTime)
            {
                _logger.LogWarning($"Session hard expired at {session.SessionExpiryTime}");
                return Json(new { isActive = false, message = "Session expired" });
            }

            // Check inactivity (1 minute for testing)
            var maxInactivity = TimeSpan.FromMinutes(1);
            if (DateTime.UtcNow - session.LastActivityTime > maxInactivity)
            {
                _logger.LogWarning($"Session inactive for >1 minute. Last activity: {session.LastActivityTime}");
                session.IsActive = false;
                await _context.SaveChangesAsync();
                return Json(new { isActive = false, message = "Inactivity logout" });
            }

            _logger.LogInformation("Session valid and active");
            return Json(new { isActive = true });
        }

        // Dashboard method with session validation
        public IActionResult Dashboard()
        {
            var userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                TempData["ErrorMessage"] = "Session expired. Please log in again.";
                return RedirectToAction("Login");
            }

            var user = _context.Users.FirstOrDefault(u => u.Id.ToString() == userId);
            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found.";
                return RedirectToAction("Login");
            }

            ViewData["UserName"] = user.FirstName;
            ViewData["UserEmail"] = user.Email;
            ViewData["UserId"] = user.Id;

            return View();
        }

        // Forgot Password GET method
        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        // Forgot Password POST method
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                TempData["ErrorMessage"] = "Email not found.";
                return View();
            }

            var resetToken = Guid.NewGuid().ToString();
            user.PasswordResetToken = resetToken;
            user.PasswordResetTokenExpiry = DateTime.Now.AddHours(1);
            await _context.SaveChangesAsync();

            var resetLink = Url.Action("ResetPassword", "Users", new { token = resetToken }, Request.Scheme);
            await SendPasswordResetEmail(user.Email, resetLink);

            TempData["SuccessMessage"] = "Password reset link has been sent to your email.";
            return RedirectToAction("Login");
        }

        // Reset Password GET method
        [HttpGet]
        public IActionResult ResetPassword(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("Token is missing or invalid.");
                TempData["ErrorMessage"] = "Invalid token.";
                return RedirectToAction("Login");
            }

            ViewData["PasswordResetToken"] = token; // Set the token to ViewData

            return View();
        }

        // Reset Password POST method
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, string token)
        {
            try
            {
                _logger.LogInformation("Entering ResetPassword method.");

                if (model.NewPassword != model.NewConfirmPassword)
                {
                    TempData["ErrorMessage"] = "The new password and confirmation password do not match.";
                   
                    return View(model);
                }

                // Fetch the user by token
                var user = _context.Users.FirstOrDefault(u => u.PasswordResetToken == token);

                if (user == null)
                {
                    
                    TempData["ErrorMessage"] = "Invalid or expired token.";
                    return RedirectToAction("Login");
                }

            

                // Check if the new password matches the last two passwords
                if (_passwordHasher.VerifyHashedPassword(user, user.PreviousPasswordHash1, model.NewPassword) == PasswordVerificationResult.Success ||
                    _passwordHasher.VerifyHashedPassword(user, user.PreviousPasswordHash2, model.NewPassword) == PasswordVerificationResult.Success)
                {
                    TempData["ErrorMessage"] = "The new password cannot be the same as any of your last two passwords.";
                   
                    return View(model);
                }

                // Hash the new password
                var hashedNewPassword = _passwordHasher.HashPassword(user, model.NewPassword);

                // Update password history
                user.PreviousPasswordHash2 = user.PreviousPasswordHash1;
                user.PreviousPasswordHash1 = user.Password;

                // Set the new hashed password
                user.Password = hashedNewPassword;

                // Clear the reset token and expiry after successful password update
                user.PasswordResetToken = string.Empty;
                user.PasswordResetTokenExpiry = null;
                user.PasswordLastChanged = DateTime.UtcNow;

                await _context.SaveChangesAsync();

                

                TempData["SuccessMessage"] = "Your password has been reset successfully.";
                return RedirectToAction("Login");
            }
            catch (Exception ex)
            {
               
                TempData["ErrorMessage"] = "An error occurred while resetting your password. Please try again.";
                return View(model);
            }
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RequestOTP(string email)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                ModelState.AddModelError("", "User  not found.");
                return View(); // You might want to redirect to a specific view or return a JSON response
            }

            // Generate and send the OTP
            await SendOTPEmail(user);

            // Save the OTP and expiry time to the database
            _context.Users.Update(user); // Mark the user entity as modified
            await _context.SaveChangesAsync(); // Save changes to the database

            TempData["SuccessMessage"] = "OTP has been sent to your email.";
            return RedirectToAction("Login"); // Redirect to a relevant page
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyOTP(string email, string enteredOTP)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                ModelState.AddModelError("", "User not found.");
                return View(); // You might want to redirect to a specific view or return a JSON response
            }

            if (VerifyOTP(user, enteredOTP))
            {
                // OTP is valid, proceed with the next step (e.g., allow access to the dashboard)
                TempData["SuccessMessage"] = "OTP verified successfully.";
                return RedirectToAction("Dashboard"); // Redirect to a relevant page
            }

            ModelState.AddModelError("", "Invalid or expired OTP.");
            return View(); // You might want to redirect to a specific view or return a JSON response
        }
        // Logout method
        public async Task<IActionResult> Logout()
        {
            var sessionToken = Request.Cookies["SessionToken"];

            if (!string.IsNullOrEmpty(sessionToken))
            {
                // Server-side cleanup
                var session = await _context.UserSessions
                    .FirstOrDefaultAsync(s => s.SessionId == sessionToken);

                if (session != null)
                {
                    session.IsActive = false;
                    session.SessionExpiryTime = DateTime.UtcNow;
                    await _context.SaveChangesAsync();
                    
                }
            }

            // Client-side cleanup
            HttpContext.Session.Clear();
            Response.Cookies.Delete("SessionToken", new CookieOptions
            {
                Path = "/Users/Login",
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            _logger.LogInformation("User logged out successfully");
            TempData["SuccessMessage"] = "You have been securely logged out.";
            return RedirectToAction("Login");
        }
        // Helper method for password strength validation

        private bool IsValidEmail(string email)
        {
            var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
            return emailRegex.IsMatch(email);
        }

        // Helper method to send password reset email
        private async Task SendPasswordResetEmail(string email, string resetLink)
        {
            var message = $"Please click the following link to reset your password: <a href=\"{resetLink}\">Reset Password</a>";
            await _emailSender.SendEmailAsync(email, "Password Reset Request", message);
        }

        // Method to verify reCAPTCHA token asynchronously using v3 and score validation
        private async Task<Tuple<bool, float>> VerifyRecaptchaAsync(string token)
        {
            using (var client = new HttpClient())
            {
                var requestContent = new StringContent(
                    $"secret={_recaptchaSecretKey}&response={token}",
                    Encoding.UTF8,
                    "application/x-www-form-urlencoded"
                );

                var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", requestContent);
                var responseContent = await response.Content.ReadAsStringAsync();
                var result = JsonConvert.DeserializeObject<RecaptchaResponse>(responseContent);

                return new Tuple<bool, float>(result.Success, result.Score);
            }
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            var sessionToken = context.HttpContext.Request.Cookies["SessionToken"];
            if (!string.IsNullOrEmpty(sessionToken))
            {
                var session = await _context.UserSessions
                    .FirstOrDefaultAsync(s => s.SessionId == sessionToken);

                if (session != null)
                {
                    // Update activity timestamps
                    var previousLastActive = session.LastActivityTime;
                    session.LastActivityTime = DateTime.UtcNow;
                    session.SessionExpiryTime = DateTime.UtcNow.AddMinutes(1); // Test timeout

                    _logger.LogInformation($"Updated session activity - Previous: {previousLastActive} | New: {session.LastActivityTime}");
                    await _context.SaveChangesAsync();
                }

            }

            await next();
        }



        public static string GenerateOTP(int length = 6)
        {
            Random random = new Random();
            return random.Next((int)Math.Pow(10, length - 1), (int)Math.Pow(10, length)).ToString();
        }

        public async Task SendOTPEmail(User user)
        {
            string otp = GenerateOTP();
            user.TwoFactorOTP = otp;
            user.OTPExpiry = DateTime.UtcNow.AddMinutes(5); // Set expiry time for 5 minutes

            // Send email logic here
            string subject = "Your OTP Code";
            string body = $"Your OTP code is: {otp}. It is valid for 5 minutes.";

            // Use your email service to send the email
            await _emailSender.SendEmailAsync(user.Email, subject, body);
        }

        public bool VerifyOTP(User user, string enteredOTP)
        {
            if (user.OTPExpiry.HasValue && user.OTPExpiry > DateTime.UtcNow)
            {
                return user.TwoFactorOTP == enteredOTP;
            }
            return false; // OTP is either expired or does not match
        }

        public class RecaptchaResponse
        {
            public bool Success { get; set; }
            public float Score { get; set; }  // Score for reCAPTCHA v3
            public string ChallengeTs { get; set; }
            public string Hostname { get; set; }
            public string ErrorCodes { get; set; }
        }

        public class PasswordPolicy
        {
            public const int MinPasswordAgeDays = 1; // Example: 1 day
            public const int MaxPasswordAgeDays = 90; // Example: 90 days
        }
    }
}