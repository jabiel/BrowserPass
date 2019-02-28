using System;
using System.Collections.Generic;

namespace BrowserPass
{
    // Missing windows.security? https://software.intel.com/en-us/articles/using-winrt-apis-from-desktop-applications
    class Program
    {
        static void Main(string[] args)
        {
            List<IPassReader> readers = new List<IPassReader>();
            readers.Add(new ChromePassReader());
            readers.Add(new FirefoxPassReader());
            readers.Add(new IE10PassReader());

            foreach (var reader in readers)
            {
                Console.WriteLine($"== {reader.BrowserName} ============================================ ");
                try
                {
                    PrintCredentials(reader.ReadPasswords());
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error reading {reader.BrowserName} passwords: " + ex.Message);
                }
            }

#if DEBUG
            Console.ReadLine();
#endif

        }

        static void PrintCredentials(IEnumerable<CredentialModel> data)
        {
            foreach (var d in data)
                Console.WriteLine($"{d.Url}\r\n\tU: {d.Username}\r\n\tP: {d.Password}\r\n");
        }
    }
}
