using System;
using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace ProvisionAutoGenKeys
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine($"Usage: {Process.GetCurrentProcess().ProcessName} <appPoolName>");
                return;
            }

            string appPoolName = args[0];

            if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)))
            {
                Console.WriteLine("This requires Administrator permissions.");
                return;
            }

            string poolSid;
            try
            {
                poolSid = new NTAccount($"IIS APPPOOL\\{appPoolName}").Translate(typeof(SecurityIdentifier)).Value;
            }
            catch (IdentityNotMappedException)
            {
                Console.WriteLine($"Application pool '{appPoolName}' account cannot be resolved.");
                return;
            }

            ProvisionAutoGenKeys(RegistryView.Registry32, "4.0.30319.0", poolSid);
            ProvisionAutoGenKeys(RegistryView.Registry64, "4.0.30319.0", poolSid);
        }

        public static void ProvisionAutoGenKeys(RegistryView regView, string expandedVersion, string sid)
        {
            var baseRegKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, regView);
            var softwareMicrosoftKey = baseRegKey.OpenSubKey("SOFTWARE\\Microsoft\\", true);

            var aspNetKey = softwareMicrosoftKey.OpenSubKey("ASP.NET", true);
            if (aspNetKey == null)
                aspNetKey = softwareMicrosoftKey.CreateSubKey("ASP.NET");

            var aspNetBaseKey = aspNetKey.OpenSubKey(expandedVersion, true);
            if (aspNetBaseKey == null)
                aspNetBaseKey = aspNetKey.CreateSubKey(expandedVersion);

            var autoGenBaseKey = aspNetBaseKey.OpenSubKey("AutoGenKeys", true);
            if (autoGenBaseKey == null)
                autoGenBaseKey = aspNetBaseKey.CreateSubKey("AutoGenKeys");

            var regSec = new RegistrySecurity();
            regSec.SetSecurityDescriptorSddlForm($"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GA;;;{sid})");

            var userAutoGenKey = autoGenBaseKey.OpenSubKey(sid, true);
            if (userAutoGenKey == null)
                userAutoGenKey = autoGenBaseKey.CreateSubKey(sid, RegistryKeyPermissionCheck.Default, regSec);
            else
                userAutoGenKey.SetAccessControl(regSec);
        }
    }
}
