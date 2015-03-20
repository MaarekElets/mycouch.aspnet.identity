using System;
using System.Collections.Generic;
using System.Linq;

namespace MyCouch.AspNet.Identity
{
    [Serializable]
    [Document(DocType = "IdentityUser", DocVersion = "1")]
    public class IdentityUser : Microsoft.AspNet.Identity.IdentityUser<string>
    {        
        public string Rev { get; set; }

        public List<string> UserRoles { get; set; }
        public List<IdentityUserLogin> Logins { get; set; }
        public List<IdentityClaim> Claims { get; set; }

        public IdentityUser()
        {
            UserRoles = new List<string>();
            Logins = new List<IdentityUserLogin>();
            Claims = new List<IdentityClaim>();            
        }

        public virtual void AssignRole(string roleId)
        {
            if (!HasRole(roleId))
                UserRoles.Add(roleId);
        }

        public virtual void RemoveRole(string roleId)
        {
            if (HasRoles())
                UserRoles.RemoveAll(i =>
                    i.Equals(roleId, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasRole(string roleId)
        {
            return HasRoles() && UserRoles.Any(i =>
                i.Equals(roleId, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasRoles()
        {
            return UserRoles != null && UserRoles.Any();
        }

        public virtual void AssignLogin(string loginProvider, string providerKey)
        {
            if (!HasLogin(loginProvider, providerKey))
                Logins.Add(new IdentityUserLogin
                {
                    LoginProvider = loginProvider,
                    ProviderKey = providerKey
                });
        }

        public virtual void RemoveLogin(string loginProvider, string providerKey)
        {
            if (HasLogins())
                Logins.RemoveAll(x =>
                    x.LoginProvider.Equals(loginProvider, StringComparison.OrdinalIgnoreCase) &&
                    x.ProviderKey.Equals(providerKey, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasLogin(string loginProvider, string providerKey)
        {
            return HasLogins() && Logins.Any(i =>
                i.LoginProvider.Equals(loginProvider, StringComparison.OrdinalIgnoreCase) &&
                i.ProviderKey.Equals(providerKey, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasLogins()
        {
            return Logins != null && Logins.Any();
        }

        public virtual void AssignClaim(string claimType, string claimValue)
        {
            if (!HasClaim(claimType, claimValue))
                Claims.Add(new IdentityClaim
                {
                    ClaimType = claimType,
                    ClaimValue = claimValue
                });
        }

        public virtual void RemoveClaim(string claimType, string claimValue)
        {
            if (HasClaims())
                Claims.RemoveAll(x =>
                    x.ClaimType.Equals(claimType, StringComparison.OrdinalIgnoreCase) &&
                    x.ClaimValue.Equals(claimValue, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasClaim(string claimType, string claimValue)
        {
            return HasClaims() && Claims.Any(i =>
                i.ClaimType.Equals(claimType, StringComparison.OrdinalIgnoreCase) &&
                i.ClaimValue.Equals(claimValue, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasClaims()
        {
            return Claims != null && Claims.Any();
        }

    }
}