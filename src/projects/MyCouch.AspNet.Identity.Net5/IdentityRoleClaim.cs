using System;
using System.Runtime.Serialization;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNet.Identity;

namespace MyCouch.AspNet.Identity
{
    [Serializable]
    public class IdentityRoleClaim
    {        

        public string ClaimType { get; set; }

        public string ClaimValue { get; set; }
        

    }
}