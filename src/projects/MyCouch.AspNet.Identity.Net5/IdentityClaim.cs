using System;

namespace MyCouch.AspNet.Identity
{
    [Serializable]
    public class IdentityClaim
    {
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }

    }
}