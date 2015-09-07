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

using AlexPilotti.FTPS.Common;
using Plossum.CommandLine;

namespace AlexPilotti.FTPS.Client.ConsoleApp
{
    [CommandLineManager(ApplicationName = "Alex FTPS",
                        Copyright = "Copyright (C) Alessandro Pilotti",
                        EnabledOptionStyles = OptionStyles.ShortUnix, IsCaseSensitive = true)]
    [CommandLineOptionGroup("commands", Name = "Commands", Require = OptionGroupRequirement.ExactlyOne)]
    [CommandLineOptionGroup("options", Name = "Options")]
    [CommandLineOptionGroup("ssloptions", Name = "SSL/TLS Options")]
    class Options
    {
#region Options

        [CommandLineOption(Name = "U", Aliases = "username", GroupId = "options",
                           Description = "Username used to perform the connection. If omitted an anonymous connection will be performed")]
        public string userName = null;

        [CommandLineOption(Name = "P", Aliases = "password", GroupId = "options",
                           Description = "Password to be used in case of non anonymous connections. If omitted it will be requested before connecting. Passing this information as a command line parameter is strongly discouraged for security reasons")]
        public string password = null;

        [CommandLineOption(Name = "h", Aliases = "hostname", GroupId = "options",
                           MinOccurs = 1,
                           Description = "Name or IP address of the remote host to connect to")]
        public string hostName = null;

        [CommandLineOption(Name = "r", Aliases = "recursive", GroupId = "options",
                           Description = "Enable recursion to download or upload entire directory trees")]
        public bool recursive = false;

        [CommandLineOption(Name = "t", Aliases = "timeout", GroupId = "options",
                           Description = "TCP/IP connection timeout in seconds (default 120s)")]
        public int timeout = 120;

        [CommandLineOption(Name = "v", Aliases = "verbose", GroupId = "options",
                           Description = "Verbose output")]
        public bool verbose = false;

        [CommandLineOption(Name = "tm", Aliases = "transferMode", GroupId = "options",
                           Description = "Transfer mode / representation type. \"ASCII\" or \"Binary\" (default)")]
        public ETransferMode transferMode = ETransferMode.Binary;

        [CommandLineOption(Name = "noCopyrightInfo", GroupId = "options",
                           Description = "Avoids displaying the copyright information header")]
        public bool noCopyrightInfo = false;

        [CommandLineOption(Name = "port", GroupId = "options", MinValue = 1,
                           Description = "TCP/IP connection port, default is: 21 for standard FTP or explicit FTPS, 990 for implicit FTPS")]
        public int port = 0;

        [CommandLineOption(Name = "oda", Aliases = "overrideDataAddress", GroupId = "options",
                           Description = "Use the control connection's remote address instead of the one returned by the PASV command")]
        public bool useCtrlEndPointAddressForData = false;

        [CommandLineOption(Name = "dm", Aliases="dataMode", GroupId = "options",
                           Description = "Active or Passive (default) data connection mode")]
        public EDataConnectionMode dataConnectionMode = EDataConnectionMode.Passive;

        [CommandLineOption(Name = "lf", Aliases = "logFile", GroupId = "options",
                           Description = "ftp commands and server replies log file name")]
        public string logFileName = null;

        [CommandLineOption(Name = "lfts", Aliases = "logFileTimeStamp", GroupId = "options",
                           Description = "Adds a timestamp to every command and reply in the log file")]
        public bool logFileTimeStamps = false;


#endregion

#region SSL Options

        [CommandLineOption(Name = "ssl", Aliases = "tls", GroupId = "ssloptions",
                           Description = "SSL/TLS support. Possible values are: \r\n\r\n" +
                                         "- ClearText (Standard FTP, no SSL/TLS support)\r\n" +
                                         "- CredentialsRequested\r\n" +
                                         "- CredentialsRequired\r\n" +
                                         "- ControlChannelRequested\r\n" +
                                         "- ControlChannelRequired\r\n" +
                                         "- DataChannelRequested (Default)\r\n" +
                                         "- DataChannelRequired\r\n" +
                                         "- ControlAndDataChannelsRequested\r\n" +
                                         "- ControlAndDataChannelsRequired\r\n" +                                         
                                         "- All (alias for \"ControlAndDataChannelsRequired\")\r\n" + 
                                         "- Implicit\r\n" +
                                         "\r\n")]
        public ESSLSupportMode sslRequestSupportMode = ESSLSupportMode.DataChannelRequested;

        [CommandLineOption(Name = "sslClientCertPath", GroupId = "ssloptions",
                           Description = "X.509 client certificate file path")]
        public string sslClientCertPath = null;

        [CommandLineOption(Name = "sslInvalidServerCertHandling", GroupId = "ssloptions",
                           Description = "Invalid X.509 server certificate handling. Valid values are: Accept, Prompt (default), Refuse")]
        public EInvalidSslCertificateHandling sslInvalidServerCertHandling = EInvalidSslCertificateHandling.Prompt;

        [CommandLineOption(Name = "sslMinKeyExStrength", GroupId = "ssloptions",
                           MinValue = 1,
                           Description = "Min. key exchange algorithm strength (e.g: 1024). Default is 0")]
        public int sslMinKeyExchangeAlgStrength = 0;

        [CommandLineOption(Name = "sslMinCipherStrength", GroupId = "ssloptions",
                           MinValue = 1,
                           Description = "Min. cipher algorithm strength (e.g: 168). Default is 0")]
        public int sslMinCipherAlgStrength = 0;

        [CommandLineOption(Name = "sslMinHashStrength", GroupId = "ssloptions",
                           MinValue = 1,
                           Description = "Min. hash algorithm strength (e.g: 160). Default is 0")]
        public int sslMinHashAlgStrength = 0;

        [CommandLineOption(Name = "sslX509ExportFormat", GroupId = "ssloptions",
                           Description = "X509 certificate export format. Not all formats are available on all platforms. "+ 
                                         "Supported values are: Cert (default), Pkcs12, SerializedCert")]
        public EX509CertificateExportFormats sslCertExportFormat = EX509CertificateExportFormats.Cert;

#endregion

#region Commands

        [CommandLineOption(Name = "?", Aliases = "help", Description = "Shows this help text", GroupId = "commands")]
        public bool helpCmd = false;

        [CommandLineOption(Name = "l", Aliases = "list", GroupId = "commands",
                           Description = "Returns the contents of the given directory, or the default directory if no name is provided")]
        public bool listDirCmd = false;

        [CommandLineOption(Name = "g", Aliases = "get,download", GroupId = "commands",
                           Description = "Downloads the given files in the current directory. File names may include wildcards. Operates recursively if the \"r\" option is specified")]
        public bool getCmd = false;

        [CommandLineOption(Name = "p", Aliases = "put,upload", GroupId = "commands",
                           Description = "Uploads the given files or directory contents. File names may include wildcards. Operates recursively if the \"r\" option is specified")]
        public bool putCmd = false;

        [CommandLineOption(Name = "d", Aliases = "delete", GroupId = "commands",
                           Description = "Deletes a remote file")]
        public bool deleteFileCmd = false;

        [CommandLineOption(Name = "rn", Aliases = "rename", GroupId = "commands",
                           Description = "Renames a remote file")]
        public bool renameFileCmd = false;

        [CommandLineOption(Name = "md", Aliases = "mkdir", GroupId = "commands",
                           Description = "Creates a remote directory")]
        public bool makeDirCmd = false;

        [CommandLineOption(Name = "rd", Aliases = "rmdir", GroupId = "commands",
                           Description = "Removes a remote directory")]
        public bool removeDirCmd = false;

        [CommandLineOption(Name = "pu", Aliases = "putUnique", GroupId = "commands",
                           Description = "Uploads a file with a unique name")]
        public bool putUniqueFileCmd = false;

        [CommandLineOption(Name = "pa", Aliases = "putAppend", GroupId = "commands",
                           Description = "Uploads a file appending it's contents if the given remote file already exists")]
        public bool putAppendFileCmd = false;

        [CommandLineOption(Name = "sys", Aliases = "system", GroupId = "commands",
                           Description = "Returns a brief description of the remote system")]
        public bool sysCmd = false;

        [CommandLineOption(Name = "expCert", Aliases = "exportSslServerCert", GroupId = "commands",
                           Description = "Exports the server's SSL/TLS X.509 certificate. The export format is managed by the \"sslX509ExportFormat\" option")]
        public bool expCertCmd = false;
        [CommandLineOption(Name = "f", Aliases = "features", GroupId = "commands",
                           Description = "Prints the list of features supported by the server, as returned by the FTP FEAT command")]
        public bool featuresCmd = false;

        [CommandLineOption(Name = "cust", Aliases = "custom", GroupId = "commands",
                           Description = "Sends the given FTP command to the server. Note: only the control channel reply is returned")]
        public bool customCmd = false;

#endregion
    }
}