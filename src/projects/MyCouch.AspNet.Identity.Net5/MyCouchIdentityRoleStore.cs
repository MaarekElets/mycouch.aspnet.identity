using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using EnsureThat;
using Microsoft.AspNet.Identity;
using MyCouch.Requests;
using System.Threading;

namespace MyCouch.AspNet.Identity.Net5
{
    public class MyCouchIdentityRoleStore<TRole> :
        IRoleStore<TRole>,
        IRoleClaimStore<TRole> where TRole : IdentityRole
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


        public MyCouchIdentityRoleStore(IMyCouchClient client)
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

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();

            if (string.IsNullOrEmpty(role.Id))
                await Client.Entities.PostAsync(role);
            else
                await Client.Entities.PutAsync(role);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();
            
            await Client.Entities.PutAsync(role);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();

            await Client.Entities.DeleteAsync(role);

            return IdentityResult.Success;
        }

        public Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(roleId, "roleId").IsNotNullOrWhiteSpace();
            return Client.Entities.GetAsync<TRole>(roleId).ContinueWith(r => r.Result.Content);
        }

        public async Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(normalizedRoleName, "normalizedRoleName").IsNotNullOrWhiteSpace();

            var request = new QueryViewRequest(_rolenamesView.DesignDocument, _rolenamesView.Name)
                .Configure(q => q.Key(normalizedRoleName)
                                 .IncludeDocs(true));

            var qr = await Client.Views.QueryAsync<string, TRole>(request);

            return qr.IsEmpty
                ? await Task.FromResult(null as TRole)
                : await Task.FromResult(qr.Rows[0].IncludedDoc);
        }

        public Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();
            Ensure.That(claim, "claim").IsNotNull();

            role.AssignClaim(claim.Type, claim.Value);            

            return Task.FromResult(0);
        }

        public Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();
            Ensure.That(claim, "claim").IsNotNull();

            role.RemoveClaim(claim.Type, claim.Value);

            return Task.FromResult(0);
        }

        public Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();

            IList<Claim> claims = role.HasClaims()
                ? role.Claims.Select(i => new Claim(i.ClaimType, i.ClaimValue)).ToList()
                : new List<Claim>();

            return Task.FromResult(claims);
        }

        public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();

            return Task.FromResult(role.NormalizedName);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("user");
            }

            if (normalizedName == null)
            {
                throw new ArgumentNullException("normalizedName");
            }

            role.NormalizedName = normalizedName;
            return Task.FromResult(0);
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();

            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.That(role, "role").IsNotNull();

            return Task.FromResult(role.Name);
        }       
        

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("user");
            }

            if (roleName == null)
            {
                throw new ArgumentNullException("roleName");
            }

            role.Name = roleName;
            return Task.FromResult(0);
        }

        

    }
}