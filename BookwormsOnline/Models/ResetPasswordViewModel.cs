using System.ComponentModel.DataAnnotations;

namespace BookwormsOnline.Models
{
    public class ResetPasswordViewModel
    {
        [Required]
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
        public string NewConfirmPassword { get; set; }

        [Required(ErrorMessage = "Password reset token is required.")]
        public string PasswordResetToken { get; set; }

        public string UserId { get; set; } 

    }
}