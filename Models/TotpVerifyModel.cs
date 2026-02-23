using System.ComponentModel.DataAnnotations;

namespace SchwabOAuthApp.Models
{
    public class TotpVerifyModel
    {
        [Required]
        [StringLength(6, MinimumLength = 6)]
        public string Code { get; set; } = string.Empty;
    }
}
