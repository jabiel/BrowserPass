using System.Collections.Generic;
using System.Linq;
using Windows.Security.Credentials;

namespace BrowserPass
{
    /// <summary>
    /// Requires:
    /// - <TargetPlatformVersion>8.0</TargetPlatformVersion> in <PropertyGroup> in project file
    /// - Reference to: Windows/Windows (will appear after adding <TargetPlatformVersion>)
    /// - reference to: C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.5.1\Facades\System.Runtime.dll
    /// </summary>
    class IE10PassReader : IPassReader
    {
        public string BrowserName { get { return "IE10/Edge"; } }

        public IEnumerable<CredentialModel> ReadPasswords()
        {
            var result = new List<CredentialModel>();
            var vault = new PasswordVault();
            var credentials = vault.RetrieveAll();
            for (var i = 0; i < credentials.Count; i++)
            {
                PasswordCredential cred = credentials.ElementAt(i);
                cred.RetrievePassword();
                
                result.Add(new CredentialModel {
                    Url = cred.Resource,
                    Username = cred.UserName,
                    Password = cred.Password
                });
            }
            return result;
        }
    }
}
