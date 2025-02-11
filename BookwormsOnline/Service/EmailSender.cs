using MimeKit;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Configuration;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.UI.Services;
using System.Net;
using MailKit.Security;

namespace BookwormsOnline.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _configuration;

        public EmailSender(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string email, string subject, string message)
        {
            var mailMessage = new MimeMessage();
            mailMessage.From.Add(new MailboxAddress("Bookworms Online", _configuration["EmailSettings:SenderEmail"]));
            mailMessage.To.Add(new MailboxAddress("", email));
            mailMessage.Subject = subject;
            mailMessage.Body = new TextPart("html") { Text = message };

            // Disable certificate validation (for testing only)
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            using (var smtpClient = new SmtpClient())
            {
                try
                {
                    // Connect to the SMTP server using STARTTLS (Secure connection)
                    await smtpClient.ConnectAsync(_configuration["EmailSettings:SmtpServer"], int.Parse(_configuration["EmailSettings:SmtpPort"]), SecureSocketOptions.StartTls);

                    // Authenticate with the SMTP server
                    await smtpClient.AuthenticateAsync(_configuration["EmailSettings:SmtpUsername"], _configuration["EmailSettings:SmtpPassword"]);

                    // Send the email
                    await smtpClient.SendAsync(mailMessage);

                    // Disconnect cleanly
                    await smtpClient.DisconnectAsync(true);
                }
                catch (Exception ex)
                {
                    // Handle any errors here (e.g., log the error)
                    Console.WriteLine($"Error sending email: {ex.Message}");
                    throw;  // Optionally rethrow or handle based on your use case
                }
            }
        }
    }
}
