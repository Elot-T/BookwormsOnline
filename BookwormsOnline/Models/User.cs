using Microsoft.AspNetCore.Identity;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.RegularExpressions;

namespace BookwormsOnline.Models
{
    // StrongPasswordAttribute validation remains the same
    public class StrongPasswordAttribute : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            string password = value as string;

            if (string.IsNullOrEmpty(password))
                return new ValidationResult("Password is required.");

            if (password.Length < 12)
                return new ValidationResult("Password must be at least 12 characters long.");

            if (!Regex.IsMatch(password, @"[a-z]"))
                return new ValidationResult("Password must contain at least one lowercase letter.");


            if (!Regex.IsMatch(password, @"[A-Z]"))
                return new ValidationResult("Password must contain at least one uppercase letter.");

            if (!Regex.IsMatch(password, @"[0-9]"))
                return new ValidationResult("Password must contain at least one number.");

            if (!Regex.IsMatch(password, @"[\W_]"))
                return new ValidationResult("Password must contain at least one special character.");

            return ValidationResult.Success;
        }
    }

    // User class
    public class User
    {
        [Key]
        public Guid Id { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 2)]
        [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "Only letters and spaces are allowed.")]
        public string FirstName { get; set; }

        [Required]
        [StringLength(100, MinimumLength = 2)]
        [RegularExpression(@"^[a-zA-Z\s]+$", ErrorMessage = "Only letters and spaces are allowed.")]
        public string LastName { get; set; }

        [Required]
        [CreditCard]
        public string CreditCardNo { get; set; }

        [Required]
        [Phone]
        public string MobileNo { get; set; }

        [Required]
        [StringLength(250)]
        public string BillingAddress { get; set; }

        [Required]
        [StringLength(250)]
        public string ShippingAddress { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }
     
        public byte[]? UploadedFile { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        //public byte[] ProfileImage { get; set; }

        [Required]
        [NotMapped]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }


        public int FailedLoginAttempts { get; set; } = 0;
        public DateTime? LockoutEnd { get; set; }


         // Ignore this field during registration
        public string PasswordResetToken { get; set; } = string.Empty;

        

        public DateTime? PasswordResetTokenExpiry { get; set; }

        public string PreviousPasswordHash1 { get; set; } = string.Empty;
        public string PreviousPasswordHash2 { get; set; } = string.Empty;


        public DateTime PasswordLastChanged { get; set; } = DateTime.UtcNow; // Default to current time
        public DateTime? PasswordExpires { get; set; } // Nullable for accounts without expiry policy

        public string? TwoFactorOTP { get; set; }
        public DateTime? OTPExpiry { get; set; }



    }

    //OTP model

  

}
