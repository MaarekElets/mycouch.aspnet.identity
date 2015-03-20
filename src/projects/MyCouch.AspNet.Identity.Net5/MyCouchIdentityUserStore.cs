using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using EnsureThat;
using Microsoft.AspNet.Identity;
using MyCouch.Requests;
using System.Threading;

namespace MyCouch.AspNet.Identity
{    
    public class MyCouchIdentityUserStore<TUser> :
        IUserStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserRoleStore<TUser>,        
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IQueryableUserStore<TUser>,
        IUserTwoFactorStore<TUser>,
        IUserSecurityStampStore<TUser> where TUser : MyCouch.AspNet.Identity.IdentityUser
    {
        private readonly ViewIdentity _usersView;
        private readonly ViewIdentity _usernamesView;
        private readonly ViewIdentity _useremailsView;
        private readonly ViewIdentity _userrolesView;
        private readonly ViewIdentity _roleusersView;
        private readonly ViewIdentity _rolenameusersView;
        private readonly ViewIdentity _rolesView;
        private readonly ViewIdentity _rolenamesView;
        private readonly ViewIdentity _claimusers;
        private readonly ViewIdentity _loginProviderProviderKeyView;

        protected bool IsDisposed { get; private set; }
        protected IMyCouchClient Client { get; private set; }

        public bool DisposeClient { get; set; }

        public MyCouchIdentityUserStore(IMyCouchClient client)
        {
            Ensure.That(client, "client").IsNotNull();
            
            _usersView = new ViewIdentity("userstore", "users");
            _usernamesView = new ViewIdentity("userstore", "usernames");
            _useremailsView = new ViewIdentity("userstore", "useremails");
            _userrolesView = new ViewIdentity("userstore", "userroles");
            _roleusersView = new ViewIdentity("userstore", "roleusers");
            _rolenameusersView = new ViewIdentity("userstore", "rolenameusers");
            _rolesView = new ViewIdentity("userstore", "roles");
            _rolenamesView = new ViewIdentity("userstore", "rolenames");
            _claimusers = new ViewIdentity("userstore", "claimusers");
            _loginProviderProviderKeyView = new ViewIdentity("userstore", "loginprovider_providerkey");
            

            DisposeClient = false;
            Client = client;
        }

        public virtual void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            ThrowIfDisposed();

            IsDisposed = true;

            if (disposing && DisposeClient && Client != null)
            {
                Client.Dispose();
                Client = null;
            }
        }

        protected virtual void ThrowIfDisposed()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.Id.ToString());

        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.UserName);
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.UserName = userName;
            return Task.FromResult(0);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.NormalizedUserName);
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.NormalizedUserName = normalizedName;
            return Task.FromResult(0);
        }

        public async virtual Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            if (string.IsNullOrEmpty(user.Id))
                await Client.Entities.PostAsync(user);
            else
                await Client.Entities.PutAsync(user);

            return IdentityResult.Success;
        }

        public async virtual Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            await Client.Entities.PutAsync(user);

            return IdentityResult.Success;
        }

        public async virtual Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            await Client.Entities.DeleteAsync(user);

            return IdentityResult.Success;
        }

        public virtual Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(userId, "userId").IsNotNullOrWhiteSpace();            
            return Client.Entities.GetAsync<TUser>(userId).ContinueWith(r => r.Result.Content);
        }

        public async virtual Task<TUser> FindByNameAsync(string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(userName, "userName").IsNotNullOrWhiteSpace();

            var request = new QueryViewRequest(_usersView.DesignDocument, _usersView.Name)
                .Configure(q => q.Key(userName)
                                 .IncludeDocs(true));

            var qr = await Client.Views.QueryAsync<string, TUser>(request);

            return qr.IsEmpty
                ? await Task.FromResult(null as TUser)
                : await Task.FromResult(qr.Rows[0].IncludedDoc);
        }

        public IQueryable<TUser> Users
        {
            get {
                var request = new QueryViewRequest(_usersView.DesignDocument, _usersView.Name)
                    .Configure(q => q.IncludeDocs(true));

                var qr = Client.Views.QueryAsync<string, TUser>(request).Result;

                return qr.IsEmpty
                ? null as IQueryable<TUser>
                : qr.Rows.Select(r => r.IncludedDoc).AsQueryable<TUser>();
            }
        }

        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            user.PasswordHash = passwordHash;

            return Task.FromResult(0);
        }

        public virtual Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            return Task.FromResult(user.PasswordHash);
        }

        public virtual Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            return Task.FromResult(user.PasswordHash != null);
        }

        public async virtual Task AddToRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();
            Ensure.That(role, "role").IsNotNullOrWhiteSpace();

            var request = new QueryViewRequest(_rolenamesView.DesignDocument, _rolenamesView.Name)
                    .Configure(q => q.IncludeDocs(true)
                                     .Key(role));

            var qr = await Client.Views.QueryAsync<string, IdentityRole>(request);

            var addRole = qr.IsEmpty ? null as IdentityRole : qr.Rows[0].IncludedDoc;

            if (addRole == null)
            {
                throw new InvalidOperationException(role + " does not exist");
            }

            user.AssignRole(addRole.Id);
            addRole.AssignUser(user.Id);
            await Client.Entities.PutAsync(addRole);
        }

        public async virtual Task RemoveFromRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();
            Ensure.That(role, "role").IsNotNullOrWhiteSpace();

            var request = new QueryViewRequest(_rolenamesView.DesignDocument, _rolenamesView.Name)
                    .Configure(q => q.IncludeDocs(true)
                                     .Key(role));

            var qr = await Client.Views.QueryAsync<string, IdentityRole>(request);

            var removeRole = qr.IsEmpty ? null as IdentityRole : qr.Rows[0].IncludedDoc;

            if (removeRole == null)
            {
                throw new InvalidOperationException(role + " does not exist");
            }

            user.RemoveRole(removeRole.Id);
            removeRole.RemoveUser(user.Id);
            await Client.Entities.PutAsync(removeRole);
        }

        public async virtual Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            var request = new QueryViewRequest(_userrolesView.DesignDocument, _userrolesView.Name)
                    .Configure(q => q.IncludeDocs(true)
                                     .StartKey("[\"" + user.Id + "\"]")
                                     .EndKey("[\"" + user.Id + "\",[]]"));

            var qr = await Client.Views.QueryAsync<string, IdentityRole>(request);

            return qr.TotalRows <= 1 ? await Task.FromResult(null as List<string>) : qr.Rows.Skip(1).Select(r => r.IncludedDoc.Name).ToList();
                        
        }

        public virtual Task<bool> IsInRoleAsync(TUser user, string role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();
            Ensure.That(role, "role").IsNotNullOrWhiteSpace();

            return Task.FromResult(user.HasRole(role));
        }

        public virtual Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();
            Ensure.That(login, "login").IsNotNull();

            user.AssignLogin(login.LoginProvider, login.ProviderKey);

            return Task.FromResult(0);
        }

        public virtual Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            IList<UserLoginInfo> logins = user.HasLogins()
                ? user.Logins.Select(i => new UserLoginInfo(i.LoginProvider, i.ProviderKey, i.ProviderDisplayName)).ToList()
                : new List<UserLoginInfo>();

            return Task.FromResult(logins);
        }

        public async virtual Task<TUser> FindAsync(UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(login, "login").IsNotNull();

            var request = new QueryViewRequest(_loginProviderProviderKeyView.DesignDocument, _loginProviderProviderKeyView.Name)
                .Configure(q => q.Key(new[] { login.LoginProvider, login.ProviderKey }));

            var qr = await Client.Views.QueryAsync<string>(request);

            return qr.IsEmpty
                ? await Task.FromResult(null as TUser)
                : await Client.Entities.GetAsync<TUser>(qr.Rows[0].Id).ContinueWith(r => r.Result.Content);
        }

        public virtual Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            IList<Claim> claims = user.HasClaims()
                ? user.Claims.Select(i => new Claim(i.ClaimType, i.ClaimValue)).ToList()
                : new List<Claim>();

            return Task.FromResult(claims);
        }

        public virtual Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            foreach (Claim claim in claims)
            {
                user.AssignClaim(claim.Type, claim.Value);
            }           

            return Task.FromResult(0);
        }

        public virtual Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            foreach (Claim claim in claims)
            {
                user.RemoveClaim(claim.Type, claim.Value);
            }            

            return Task.FromResult(0);
        }

        

        public virtual Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            user.SecurityStamp = stamp;

            return Task.FromResult(0);
        }

        public virtual Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(user, "user").IsNotNull();

            return Task.FromResult(user.SecurityStamp);
        }      

        public virtual Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(loginProvider, "loginProvider").IsNotNull();
            Ensure.That(providerKey, "providerKey").IsNotNull();

            user.RemoveLogin(loginProvider, providerKey);

            return Task.FromResult(0);
        }

        public virtual async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(loginProvider, "loginProvider").IsNotNull();
            Ensure.That(providerKey, "providerKey").IsNotNull();

            var request = new QueryViewRequest(_loginProviderProviderKeyView.DesignDocument, _loginProviderProviderKeyView.Name)
                .Configure(q => q.Key(new[] { loginProvider, providerKey }));

            var qr = await Client.Views.QueryAsync<string>(request);

            return qr.IsEmpty
                ? await Task.FromResult(null as TUser)
                : await Client.Entities.GetAsync<TUser>(qr.Rows[0].Id).ContinueWith(r => r.Result.Content);

        }
    
        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }
            if (newClaim == null)
            {
                throw new ArgumentNullException("newClaim");
            }
            
            var matchedClaims = user.Claims.Where(c => c.ClaimValue == claim.Value && c.ClaimType == claim.Type).ToList();

            foreach (var matchedClaim in matchedClaims)
            {
                matchedClaim.ClaimValue = newClaim.Value;
                matchedClaim.ClaimType = newClaim.Type;
            }

            return Task.FromResult(0);
        }        

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var request = new QueryViewRequest(_claimusers.DesignDocument, _claimusers.Name)
                    .Configure(q => q.IncludeDocs(true)
                                     .Key("[\"" + claim.Type + "\",[\"" + claim.Value + "\"]"));
                                     

            var qr = await Client.Views.QueryAsync<string, TUser>(request);

            return qr.TotalRows <= 1 ? await Task.FromResult(null as List<TUser>) : qr.Rows.Select(r => r.IncludedDoc).ToList();
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(roleName, "roleName").IsNotNull();

            var request = new QueryViewRequest(_rolenameusersView.DesignDocument, _rolenameusersView.Name)
                    .Configure(q => q.IncludeDocs(true)
                                     .StartKey("[\"" + roleName + "\"]")
                                     .EndKey("[\"" + roleName + "\",[]]"));

            var qr = await Client.Views.QueryAsync<string, TUser>(request);

            return qr.TotalRows <= 1 ? await Task.FromResult(null as List<TUser>) : qr.Rows.Skip(1).Select(r => r.IncludedDoc).ToList();
        }

        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.Email = email;
            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(normalizedEmail, "normalizedEmail").IsNotNullOrWhiteSpace();

            var request = new QueryViewRequest(_useremailsView.DesignDocument, _useremailsView.Name)
                .Configure(q => q.Key(normalizedEmail)
                                 .IncludeDocs(true));

            var qr = await Client.Views.QueryAsync<string, TUser>(request);

            return qr.IsEmpty
                ? await Task.FromResult(null as TUser)
                : await Task.FromResult(qr.Rows[0].IncludedDoc);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.NormalizedEmail = normalizedEmail;
            return Task.FromResult(0);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            throw new NotImplementedException();
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEnd = lockoutEnd;
            return Task.FromResult(0);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult(0);
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.TwoFactorEnabled);
        }
       
    }
}