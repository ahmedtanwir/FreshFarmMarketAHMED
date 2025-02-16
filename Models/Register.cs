using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;  

namespace FreshFarmMarket.Models
{
    public class Register
    {
        [Required(ErrorMessage = "Full Name is required.")]
        [StringLength(100, ErrorMessage = "Full Name cannot be longer than 100 characters.")]
        public string FullName { get; set; }

        [Required(ErrorMessage = "Credit Card Number is required.")]
        [RegularExpression(@"^\d{16}$", ErrorMessage = "Credit Card number must be exactly 16 digits.")]
        public string CreditCardNo { get; set; }

        [Required(ErrorMessage = "Gender is required.")]
        public string Gender { get; set; }

        [Required(ErrorMessage = "Mobile Number is required.")]
        [Phone(ErrorMessage = "Invalid Phone Number.")]
        [RegularExpression(@"^\d{8,15}$", ErrorMessage = "Mobile number must be between 8 to 15 digits.")]
        public string MobileNo { get; set; }

        [Required(ErrorMessage = "Delivery Address is required.")]
        [StringLength(500, ErrorMessage = "Delivery Address cannot be longer than 500 characters.")]
        public string DeliveryAddress { get; set; }

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid Email Address.")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long.")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Confirm Password is required.")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public string ConfirmPassword { get; set; }

        [Required(ErrorMessage = "About Me is required.")]
        [StringLength(500, ErrorMessage = "About Me section cannot exceed 500 characters.")]
        public string AboutMe { get; set; }

        [Required(ErrorMessage = "Please upload a photo.")]
        [DataType(DataType.Upload)]
        [AllowedFileExtensions(new string[] { ".jpg", ".jpeg", ".png" }, ErrorMessage = "Only JPG, JPEG, or PNG files are allowed.")]
        public IFormFile Photo { get; set; }
    }

  
    public class AllowedFileExtensionsAttribute : ValidationAttribute
    {
        private readonly string[] _extensions;

        public AllowedFileExtensionsAttribute(string[] extensions)
        {
            _extensions = extensions;
        }

        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            if (value is IFormFile file)
            {
                var fileExtension = Path.GetExtension(file.FileName).ToLowerInvariant();
                if (!_extensions.Contains(fileExtension))
                {
                    return new ValidationResult($"Only {string.Join(", ", _extensions)} files are allowed.");
                }
            }
            return ValidationResult.Success;
        }
    }
}