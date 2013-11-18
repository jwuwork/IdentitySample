using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

namespace IdentitySample.Validators
{
    public class AccountValidator<TUser> : IIdentityValidator<TUser> where TUser : IUser
    {
        public bool AllowOnlyAlphanumericUserNames { get; set; }

        private UserManager<TUser> Manager { get; set; }

        public AccountValidator(UserManager<TUser> manager)
        {
            if (manager == null)
            {
                throw new ArgumentNullException("manager");
            }
            this.AllowOnlyAlphanumericUserNames = false;
            this.Manager = manager;
        }

        private async Task ValidateUserName(TUser user, List<string> errors)
        {
            if (string.IsNullOrWhiteSpace(user.UserName))
            {
                errors.Add("Email is required.");
            }
            else if (this.AllowOnlyAlphanumericUserNames && !Regex.IsMatch(user.UserName, @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}"))
            {
                errors.Add(string.Format((IFormatProvider)CultureInfo.CurrentCulture, "Email is invalid.", new object[1]
                {
                    (object) user.UserName
                }));
            }
            else
            {
                TUser owner = await this.Manager.FindByNameAsync(user.UserName);
                if ((object)owner != null && owner.Id != user.Id)
                    errors.Add(string.Format((IFormatProvider)CultureInfo.CurrentCulture, "Email already exists.", new object[1]
                  {
                    (object) user.UserName
                  }));
            }
        }

        public async Task<IdentityResult> ValidateAsync(TUser item)
        {
            if ((object)item == null)
            {
                throw new ArgumentNullException("entity");
            }
            var errors = new List<string>();
            await this.ValidateUserName(item, errors);
            return errors.Count <= 0 ? IdentityResult.Success : IdentityResult.Failed(errors.ToArray());
        }
    }
}