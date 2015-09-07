/*
 *  Copyright 2008 Alessandro Pilotti
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA 
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AlexPilotti.FTPS.Client.ConsoleApp
{
    class Utility
    {
        public static string FormatTimeSpan(TimeSpan ts)
        {
            return String.Format("{0:00}:{1:00}:{2:00}.{3:00}", ts.Hours, ts.Minutes, ts.Seconds, ts.Milliseconds / 10D);
        }

        public static string GetCertificateInfo(X509Certificate certificate)
        {
            StringBuilder certInfo = new StringBuilder();

            //Note: certificate.ToString() returns just the class name in Mono 2.0

            // Simulate the .Net frameworks 2.0 ToString()
            certInfo.AppendLine("[Subject]");
            certInfo.AppendLine(certificate.Subject);
            certInfo.AppendLine("");
            certInfo.AppendLine("[Issuer]");
            certInfo.AppendLine(certificate.Issuer);
            certInfo.AppendLine("");
            certInfo.AppendLine("[Serial Number]");
            certInfo.AppendLine(certificate.GetSerialNumberString());
            certInfo.AppendLine("");
            certInfo.AppendLine("[Not Before]");
            certInfo.AppendLine(certificate.GetEffectiveDateString());
            certInfo.AppendLine("");
            certInfo.AppendLine("[Not After]");
            certInfo.AppendLine(certificate.GetExpirationDateString());
            certInfo.AppendLine("");
            certInfo.AppendLine("[Thumbprint]");
            certInfo.AppendLine(certificate.GetCertHashString());

            return certInfo.ToString();
        }

        public static bool ConsoleConfirm(string prompt)
        {
            string res;
            do
            {
                Console.Write(prompt + " ");
                res = Console.ReadLine().ToUpper();
            }
            while (res != "Y" && res != "N");

            return (res == "Y");
        }

        /// <summary>
        /// Read a password without echoing the chars.
        /// </summary>
        /// <returns></returns>
        public static string ReadConsolePassword()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    password += info.KeyChar;
                    info = Console.ReadKey(true);
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password.Substring
                        (0, password.Length - 1);
                    }
                    info = Console.ReadKey(true);
                }
            }
            for (int i = 0; i < password.Length; i++)
                Console.Write("*");
            return password;
        }
    }
}
