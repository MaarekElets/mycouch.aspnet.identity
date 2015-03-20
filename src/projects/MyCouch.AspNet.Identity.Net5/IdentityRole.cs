using System;
using System.Collections.Generic;
using System.Linq;

namespace MyCouch.AspNet.Identity
{
    [Serializable]
    [Document(DocType = "IdentityRole", DocVersion = "1")]
    public class IdentityRole : Microsoft.AspNet.Identity.IdentityRole<string> 
    {
        public string rev { get; set; }

        new public List<IdentityClaim> Claims { get; set; }
        public List<string> UserRoles { get; set; }

        public IdentityRole() {
            Claims = new List<IdentityClaim>();
            UserRoles = new List<string>();            
        }
       
        public IdentityRole(string roleName) : this()
        {
            Name = roleName;                        
        }

        public virtual void AssignUser(string userId)
        {
            if (!HasUser(userId))
                UserRoles.Add(userId);
        }

        public virtual void RemoveUser(string userId)
        {
            if (HasUsers())
                UserRoles.RemoveAll(i =>
                    i.Equals(userId, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasUser(string userId)
        {
            return HasUsers() && UserRoles.Any(i =>
                i.Equals(userId, StringComparison.OrdinalIgnoreCase));
        }

        public virtual bool HasUsers()
        {
            return UserRoles != null && UserRoles.Any();
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