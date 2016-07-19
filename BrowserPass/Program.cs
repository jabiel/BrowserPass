using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BrowserPass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(" =========== Chrome =========== ");
            try
            {
                var chrome = new ChromePassReader().ReadPasswords();
                PrintCredentials(chrome);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Cannot get chrome passwords: " + ex.Message);
            }
            

            Console.WriteLine("");
            Console.WriteLine(" =========== IE10/Edge  =========== ");
            try
            {
                var ie10 = new IE10PassReader().ReadPasswords();
                PrintCredentials(ie10);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Cannot get chrome passwords: " + ex.Message);
            }
            
            Console.WriteLine("");
            Console.WriteLine(" =========== Firefox =========== ");
            try
            {
                var ff = new FirefoxPassReader().ReadPasswords();
                PrintCredentials(ff);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Cannot get chrome passwords: " + ex.Message);
            }
            

            Console.ReadKey();
        }

        static void PrintCredentials(IEnumerable<BrowserCredential> data)
        {
            foreach (var d in data)
                Console.WriteLine($"{d.Url}\t {d.Username}\t {d.Password}");
        }
    }
}
