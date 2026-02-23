using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace SchwabOAuthApp.Filters
{
    public class TotpAuthorizationFilter : IAuthorizationFilter
    {
        private readonly SchwabOAuthApp.Services.ITotpService _totpService;

        public TotpAuthorizationFilter(SchwabOAuthApp.Services.ITotpService totpService)
        {
            _totpService = totpService;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            // Get the action and controller names
            var actionName = context.RouteData.Values["action"]?.ToString();
            var controllerName = context.RouteData.Values["controller"]?.ToString();

            // Allow access to TOTP setup and verification pages
            var allowedActions = new[] { "TotpSetup", "ConfirmSetup", "TotpVerify", "VerifyTotpCode" };
            if (allowedActions.Contains(actionName))
            {
                return;
            }

            // Check if TOTP is set up
            if (!_totpService.IsSetup())
            {
                // Redirect to setup page
                context.Result = new RedirectToActionResult("TotpSetup", "Schwab", null);
                return;
            }

            // Check if user is verified
            var totpVerified = context.HttpContext.Session.GetString("totp_verified");
            if (totpVerified != "true")
            {
                // Redirect to verification page
                context.Result = new RedirectToActionResult("TotpVerify", "Schwab", null);
                return;
            }
        }
    }
}
