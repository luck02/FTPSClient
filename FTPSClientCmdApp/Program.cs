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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using AlexPilotti.FTPS.Common;
using Plossum.CommandLine;
using System.Reflection;

namespace AlexPilotti.FTPS.Client.ConsoleApp
{
    enum EInvalidSslCertificateHandling { Refuse, Accept, Prompt }
    enum EX509CertificateExportFormats { Cert, SerializedCert, Pkcs12 }

    class Program
    {
        private static Options options = new Options();
        private static IList<string> commandArguments;
        const string programName = "ftps";
        const string logDateTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffffffK";

        private static int consoleFormatWidth = 80;
        // Needed to show progress during a file transfer
        private static int lastCharPos = 0;

        // Set during multiple file transfers
        private static int filesTrasferredCount = 0;

        private static Stopwatch watch = new Stopwatch();

        private static StreamWriter swLog = null;

        static int Main(string[] args)
        {
            int retVal = -1;

            SetConsoleFormatWidth();

            try
            {
                CommandLineParser parser = new CommandLineParser(options);
                parser.AddAssignmentCharacter(':', OptionStyles.All);

                IList<string> additionalErrors;
                ParseArguments(parser, out additionalErrors);

                if (options.helpCmd || parser.HasErrors || additionalErrors.Count > 0)
                    ShowHelpInfoAndErrors(parser, additionalErrors, !options.helpCmd);
                else
                {
                    if (!options.noCopyrightInfo)
                        ShowHeader();

                    DoCommands();

                    retVal = 0;
                }                
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine();
                Console.Error.WriteLine("ERROR: " + ex.Message);

                if (options.verbose && ex.InnerException != null)
                    Console.Error.WriteLine("Inner exception: " + ex.InnerException);
            }

            return retVal;
        }

        private static void SetConsoleFormatWidth()
        {
            try
            {
                consoleFormatWidth = Console.WindowWidth - 1;
            }
            catch (Exception)
            {
                consoleFormatWidth = 80;
            } 
        }

        private static void DoCommands()
        {
            try
            {
                using (FTPSClient client = new FTPSClient())
                {
                    InitLogFile(client);

                    DoConnect(client);

                    if (options.listDirCmd)
                        DoList(client);

                    if (options.getCmd)
                        DoGet(client);

                    if (options.putCmd)
                        DoPut(client);

                    if (options.deleteFileCmd)
                        DoDeleteFile(client);

                    if (options.renameFileCmd)
                        DoRenameFile(client);

                    if (options.makeDirCmd)
                        DoMakeDir(client);

                    if (options.removeDirCmd)
                        DoRemoveDir(client);

                    if (options.putUniqueFileCmd)
                        DoPutUniqueFile(client);

                    if (options.putAppendFileCmd)
                        DoAppendFile(client);

                    if (options.sysCmd)
                        DoSys(client);

                    if (options.expCertCmd)
                        DoExportSslServerCert(client);

                    if (options.featuresCmd)
                        DoFeatures(client);

                    if (options.customCmd)
                        DoCustomCommand(client);

                    if (options.verbose)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Command completed");
                    }
                }
            }
            finally
            {
                if (swLog != null)
                {
                    swLog.Close();
                    swLog = null;
                }
            }
        }

        private static void InitLogFile(FTPSClient client)
        {
            if (options.logFileName != null)
            {
                swLog = new StreamWriter(options.logFileName);
                client.LogCommand += new LogCommandEventHandler(client_LogCommand);
                client.LogServerReply += new LogServerReplyEventHandler(client_LogServerReply);
            }
        }

        static void client_LogCommand(object sender, LogCommandEventArgs args)
        {
            if (options.logFileTimeStamps)
                swLog.WriteLine(DateTime.Now.ToString(logDateTimeFormat));

            // Hide password
            string cmdText = args.CommandText;
            if (cmdText.StartsWith("PASS "))
                cmdText = "PASS ********";

            swLog.WriteLine(cmdText);
        }

        static void client_LogServerReply(object sender, LogServerReplyEventArgs args)
        {
            if (options.logFileTimeStamps)
                swLog.WriteLine(DateTime.Now.ToString(logDateTimeFormat));
            swLog.WriteLine(string.Format("{0} {1}", args.ServerReply.Code, args.ServerReply.Message));
        }

        private static void DoCustomCommand(FTPSClient client)
        {
            FTPReply reply = client.SendCustomCommand(commandArguments[0]);

            Console.WriteLine("Server reply: " + reply.ToString());
        }

        private static void DoFeatures(FTPSClient client)
        {
            IList<string> features = client.GetFeatures();

            Console.WriteLine();

            if(features == null)
                Console.WriteLine("The FEAT command is not supported by the server");
            else
            {                
                Console.WriteLine("Features:");
                Console.WriteLine();

                foreach (string feature in features)
                    Console.WriteLine(feature);                
            }            
        }

        private static void DoExportSslServerCert(FTPSClient client)
        {
            if (client.SslSupportCurrentMode == ESSLSupportMode.ClearText)
                throw new Exception("The FTP connection is not encrypted");

            X509Certificate cert = client.RemoteCertificate;
            if (cert == null)
                throw new Exception("No remote SSL/TLS X.509 certificate available");

            X509ContentType exportX509ContentType = X509ContentType.Cert;
            switch (options.sslCertExportFormat)
            {
                case EX509CertificateExportFormats.Cert:
                    exportX509ContentType = X509ContentType.Cert;
                    break;
                case EX509CertificateExportFormats.SerializedCert:
                    exportX509ContentType = X509ContentType.SerializedCert;
                    break;
                case EX509CertificateExportFormats.Pkcs12:
                    exportX509ContentType = X509ContentType.Pkcs12;
                    break;
            }

            byte[] exportedCert = cert.Export(exportX509ContentType);

            using (Stream s = File.Create(commandArguments[0]))
                s.Write(exportedCert, 0, exportedCert.Length);
        }

        private static void ShowHelpInfoAndErrors(CommandLineParser parser, IList<string> additionalErrors, bool showErrors)
        {
            ShowHeader();

            Console.WriteLine();
            Console.WriteLine("Usage: " + programName + " [options] <command> [command specific arguments]");
            Console.WriteLine();
            Console.WriteLine();

            if (showErrors)
            {
                if (parser.HasErrors)
                    Console.WriteLine(parser.UsageInfo.GetErrorsAsString(consoleFormatWidth));

                if (additionalErrors.Count > 0)
                    WriteAdditionalErrors(additionalErrors);

                Console.WriteLine();
            }
            
            Console.WriteLine(parser.UsageInfo.GetOptionsAsString(consoleFormatWidth));

            ShowUsageSamples();
        }

        private static void ShowUsageSamples()
        {
            Console.WriteLine();
            Console.WriteLine("QUICK USAGE SAMPLES:");
            Console.WriteLine();
            Console.WriteLine("* Show the directory contents of a remote directory using anonymous");
            Console.WriteLine("  authentication on standard FTP (without SSL/TLS):");
            Console.WriteLine();
            Console.WriteLine(programName + @" -h ftp.yourserver.com -ssl ClearText -l /pub");
            Console.WriteLine();
            Console.WriteLine("* Connect to the server using SSL/TLS during authentication or");
            Console.WriteLine("  clear text mode (standard FTP) if FTPS is not supported:");
            Console.WriteLine();
            Console.WriteLine(programName + @" -h ftp.yourserver.com -U alex -l /pub");
            Console.WriteLine();
            Console.WriteLine("* Download a remote file using control and data channel SSL/TLS encryption:");
            Console.WriteLine();
            Console.WriteLine(programName + @" -h ftp.yourserver.com -U alex -ssl All -g /remote/path/somefile.txt /local/path/");
            Console.WriteLine();
            Console.WriteLine("* Upload a local file with a control channel encrypted");
            Console.WriteLine("  during authentication only:");
            Console.WriteLine();
            Console.WriteLine(programName + @" -h ftp.yourserver.com -U alex -ssl CredentialsRequired -p /local/path/somefile.txt /remote/path/");
            Console.WriteLine();
            Console.WriteLine("* Recursively download a whole directory tree:");
            Console.WriteLine();
            Console.WriteLine(programName + @" -h ftp.yourserver.com -r -g /remote/path/* \local\path\");
            Console.WriteLine();
            Console.WriteLine("* Implicit FTPS on port 21:");
            Console.WriteLine();
            Console.WriteLine(programName + @" -h ftp.yourserver.com -port 21 -ssl Implicit -U alex -l");
            Console.WriteLine();
            Console.WriteLine("ADDITIONAL INFO AND HELP: http://www.codeplex.com/ftps");
        }

        private static void ShowHeader()
        {
            Console.WriteLine("Alex FTPS version " + GetAssemblyVersion());
            Console.WriteLine("Copyright (C) Alessandro Pilotti 2008-2009");
            Console.WriteLine();
            Console.WriteLine("http://www.codeplex.com/ftps");
            Console.WriteLine("info@pilotti.it");
            Console.WriteLine();
            Console.WriteLine("This is free software, you may use it under the terms of");            
            Console.WriteLine("the LGPL license <http://www.gnu.org/copyleft/lesser.html>");            
        }

        private static string GetAssemblyVersion()
        {
            Version version = Assembly.GetExecutingAssembly().GetName().Version;
            return string.Format("{0}.{1}.{2}", version.Major, version.Minor, version.Build);
        }

        private static void ParseArguments(CommandLineParser parser, out IList<string> additionalErrors)
        {            
            parser.Parse();

            additionalErrors = new List<string>();

            // Get the arguments left off by the parser
            commandArguments = new List<string>();

            if (!parser.HasErrors)
            {
                PerformAdditionalCommandLineValidation(parser, additionalErrors);
                // The remaining arguments are the valid command parameters
                (commandArguments as List<string>).AddRange(parser.RemainingArguments);
            }
        }

        private static void WriteAdditionalErrors(IList<string> additionalErrors)
        {
            int indentWidth = 3;

            Console.WriteLine("Errors:");
            foreach (string message in additionalErrors)
                Console.WriteLine(Plossum.StringFormatter.FormatInColumns(indentWidth, 1, new Plossum.ColumnInfo(1, "*"),
                                  new Plossum.ColumnInfo(consoleFormatWidth - 1 - indentWidth - 1, message)));            
        }

        private static void PerformAdditionalCommandLineValidation(CommandLineParser parser, IList<string> additionalErrors)
        {
            string messageTemplate = "Wrong arguments number supplied for the \"{0}\" command.\r\n" + 
                                     "Usage: " + programName + " [options] {1}";

            if (options.listDirCmd && parser.RemainingArguments.Count > 1)
                additionalErrors.Add(string.Format(messageTemplate, "list", "[remoteDir]"));           

            if(options.getCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "get", "<remoteFile|remoteFilePattern> [localDir|localFile]"));

            if (options.putCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "put", "<localFile|localFilePattern> [remoteDir|remoteFile]"));

            if (options.deleteFileCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "delete", "<remoteFile>"));

            if (options.renameFileCmd && parser.RemainingArguments.Count != 2)
                additionalErrors.Add(string.Format(messageTemplate, "rename", "<fromRemoteFile> <toRemoteFile>"));

            if (options.makeDirCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "mkdir", "<remoteDir>"));

            if (options.removeDirCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "rmdir", "<remoteDir>"));

            if (options.putUniqueFileCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "putUnique", "<localFile> [remoteDir]"));

            if (options.putAppendFileCmd && (parser.RemainingArguments.Count == 0 || parser.RemainingArguments.Count > 2))
                additionalErrors.Add(string.Format(messageTemplate, "putAppend", "<localFile> [remoteDir|remoteFile]"));

            if (options.sysCmd && parser.RemainingArguments.Count > 0)
                additionalErrors.Add(string.Format(messageTemplate, "sys", ""));

            if (options.expCertCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "exportSslServerCert", "<certFileName>"));

            if (options.featuresCmd && parser.RemainingArguments.Count > 0)
                additionalErrors.Add(string.Format(messageTemplate, "features", ""));

            if (options.customCmd && parser.RemainingArguments.Count != 1)
                additionalErrors.Add(string.Format(messageTemplate, "custom", "<customFTPCommand>"));
        }

        private static void DoSys(FTPSClient client)
        {
            string systemInfo = client.GetSystem();
            Console.WriteLine("Remote system: \"" + systemInfo + "\"");
        }

        private static void DoDeleteFile(FTPSClient client)
        {
            client.DeleteFile(NormalizeRemotePath(commandArguments[0]));
        }

        private static void DoRenameFile(FTPSClient client)
        {
            client.RenameFile(NormalizeRemotePath(commandArguments[0]), 
                              NormalizeRemotePath(commandArguments[1]));
        }

        private static void DoPutUniqueFile(FTPSClient client)
        {
            string localPathName = commandArguments[0];

            if(commandArguments.Count > 1)
            {
                string remoteDirName = NormalizeRemotePath(commandArguments[1]);
                client.SetCurrentDirectory(remoteDirName);
            }

            string remoteFileName;
            client.PutUniqueFile(localPathName, out remoteFileName, new FileTransferCallback(TransferCallback));            

            Console.WriteLine("Unique file uploaded. File name: \"" + remoteFileName + "\"");
        }

        private static void DoAppendFile(FTPSClient client)
        {
            string localPathName = commandArguments[0];
            string remotePathName = GetRemotePathName(localPathName);
            client.AppendFile(localPathName, remotePathName, new FileTransferCallback(TransferCallback));            
        }

        private static void DoMakeDir(FTPSClient client)
        {
            client.MakeDir(NormalizeRemotePath(commandArguments[0]));
        }

        private static void DoRemoveDir(FTPSClient client)
        {
            client.RemoveDir(NormalizeRemotePath(commandArguments[0]));
        }

        private static void DoConnect(FTPSClient client)
        {
            WriteCredentialsEncryptionWarning();

            CheckPassword();

            int port = options.port;
            if (port == 0)
                port = (options.sslRequestSupportMode & ESSLSupportMode.Implicit) == ESSLSupportMode.Implicit ? 990 : 21;

            NetworkCredential credential = null;
            if (options.userName != null && options.userName.Length > 0)
                credential = new NetworkCredential(options.userName, options.password);

            X509Certificate x509ClientCert = null;
            if (options.sslClientCertPath != null)
                x509ClientCert = X509Certificate.CreateFromCertFile(options.sslClientCertPath);

            client.Connect(options.hostName, port,
                           credential,
                           options.sslRequestSupportMode,
                           new RemoteCertificateValidationCallback(ValidateTestServerCertificate),
                           x509ClientCert, 
                           options.sslMinKeyExchangeAlgStrength, 
                           options.sslMinCipherAlgStrength,
                           options.sslMinHashAlgStrength,
                           options.timeout * 1000,
                           options.useCtrlEndPointAddressForData,
                           options.dataConnectionMode);

            // client.Connect already sets binary by default
            if (options.transferMode != ETransferMode.Binary)
                client.SetTransferMode(options.transferMode);

            WriteConnectionInfo(client);

            WriteSslStatus(client);
        }

        private static void WriteConnectionInfo(FTPSClient client)
        {
            if (options.verbose)
            {
                Console.WriteLine();
                Console.WriteLine("Banner message:");
                Console.WriteLine();
                Console.WriteLine(client.BannerMessage);
                Console.WriteLine();

                Console.WriteLine("Welcome message:");
                Console.WriteLine();
                Console.WriteLine(client.WelcomeMessage);
                Console.WriteLine();

                Console.WriteLine("Text encoding: " + client.TextEncoding.ToString());
                Console.WriteLine("Transfer mode: " + client.TransferMode.ToString());
            }
        }

        private static void WriteCredentialsEncryptionWarning()
        {
            if (options.userName != null && (options.sslRequestSupportMode & ESSLSupportMode.CredentialsRequired) != ESSLSupportMode.CredentialsRequired)
            {
                Console.WriteLine();

                if ((options.sslRequestSupportMode & ESSLSupportMode.CredentialsRequested) != ESSLSupportMode.CredentialsRequested)
                    Console.WriteLine("WARNING: Credentials will be sent in clear text");
                else
                    Console.WriteLine("WARNING: Credentials might be sent in clear text");
                Console.WriteLine("Please see the \"ssl\" option for details");
            }
        }

        private static void WriteSslStatus(FTPSClient client)
        {
            if (options.verbose)
            {
                string sslSupportDesc = null;

                if ((client.SslSupportCurrentMode & ESSLSupportMode.CredentialsRequested) == ESSLSupportMode.CredentialsRequested)
                    sslSupportDesc = "Credentials";
                if ((client.SslSupportCurrentMode & ESSLSupportMode.ControlChannelRequested) == ESSLSupportMode.ControlChannelRequested)
                    sslSupportDesc += ", Commands";

                if ((client.SslSupportCurrentMode & ESSLSupportMode.DataChannelRequested) == ESSLSupportMode.DataChannelRequested)
                {
                    if (sslSupportDesc != null)
                        sslSupportDesc += ", ";
                    sslSupportDesc += "Data";
                }

                if (sslSupportDesc == null)
                    sslSupportDesc = "None";

                Console.WriteLine();
                Console.WriteLine("SSL/TLS support: " + sslSupportDesc);

                SslInfo sslInfo = client.SslInfo;
                if (sslInfo != null)
                {
                    Console.WriteLine("SSL/TLS Info: " + sslInfo.ToString());
                }
            }
        }

        private static void DoGet(FTPSClient client)
        {
            string remotePathPattern = commandArguments[0];
            
            if (IsWildCardPath(remotePathPattern))
                DoWildCardGet(client, remotePathPattern);
            else
                DoSingleFileGet(client, remotePathPattern);
        }

        private static void DoSingleFileGet(FTPSClient client, string remotePathName)
        {
            string localPathName = null;
            string localDirName = null;
            if (commandArguments.Count > 1)
            {
                if (Directory.Exists(commandArguments[1]))
                    localDirName = commandArguments[1];
                else
                    localPathName = commandArguments[1];

            }
            else
                localDirName = Directory.GetCurrentDirectory();

            if (localPathName == null)
            {                
                string remoteFileName = Path.GetFileName(remotePathName);
                localPathName = Path.Combine(localDirName, remoteFileName);
            }

            client.GetFile(remotePathName, localPathName, new FileTransferCallback(TransferCallback));
        }

        private static void DoWildCardGet(FTPSClient client, string remotePathPattern)
        {
            string remoteDirName = NormalizeRemotePath(Path.GetDirectoryName(remotePathPattern));
            string remoteFilePattern = Path.GetFileName(remotePathPattern);

            filesTrasferredCount = 0;

            string localDirName;
            if (commandArguments.Count > 1)
                localDirName = commandArguments[1];
            else
                localDirName = Directory.GetCurrentDirectory();

            client.GetFiles(remoteDirName, localDirName, remoteFilePattern, EPatternStyle.Wildcard, options.recursive, new FileTransferCallback(TransferCallback));

            Console.WriteLine();
            if (filesTrasferredCount > 0)
                Console.WriteLine("Downloaded files: {0}", filesTrasferredCount);
            else
                Console.Error.WriteLine("WARNING: No files downloaded");            
        }

        private static bool IsWildCardPath(string pathName)
        {
            return pathName.Contains("*") || pathName.Contains("?");
        }

        private static void DoPut(FTPSClient client)
        {
            string localPathPattern = commandArguments[0];            

            if (IsWildCardPath(localPathPattern))
                DoWildCardPut(client, localPathPattern);
            else
                DoSingleFilePut(client, localPathPattern);            
        }

        private static void DoWildCardPut(FTPSClient client, string localPathPattern)
        {
            string localDirName = Path.GetDirectoryName(localPathPattern);
            string localFilePattern = Path.GetFileName(localPathPattern);

            filesTrasferredCount = 0;

            string remoteDirName = null;
            if (commandArguments.Count > 1)
                remoteDirName = NormalizeRemotePath(commandArguments[1]);

            client.PutFiles(localDirName, remoteDirName, localFilePattern, EPatternStyle.Wildcard, options.recursive, new FileTransferCallback(TransferCallback));

            Console.WriteLine();
            if (filesTrasferredCount > 0)
                Console.WriteLine("Uploaded files: {0}", filesTrasferredCount);
            else
                Console.Error.WriteLine("WARNING: No files uploaded");            
        }

        private static void DoSingleFilePut(FTPSClient client, string localPathName)
        {
            string remotePathName = GetRemotePathName(localPathName);
            client.PutFile(localPathName, remotePathName, new FileTransferCallback(TransferCallback));
        }

        private static string GetRemotePathName(string localPathName)
        {
            string remotePathName = null;
            string localFileName = Path.GetFileName(localPathName);
            if (commandArguments.Count > 1)
            {
                string str = NormalizeRemotePath(commandArguments[1]);

                if (str.EndsWith("/"))
                    remotePathName = str + localFileName;
                else
                    remotePathName = str;
            }
            else
                remotePathName = localFileName;
            return remotePathName;
        }

        /// <summary>
        /// Replaces the "\" path separator with "/"
        /// </summary>
        /// <param name="remotePath"></param>
        /// <returns></returns>
        private static string NormalizeRemotePath(string remotePath)
        {
            return remotePath != null ? remotePath.Replace("\\", "/") : null;
        }

        private static void DoList(FTPSClient client)
        {
            string remoteDirName = null;
            if (commandArguments.Count > 0)
                remoteDirName = NormalizeRemotePath(commandArguments[0]);
            else
                remoteDirName = client.GetCurrentDirectory();

            Console.WriteLine();
            Console.WriteLine("Remote directory: " + remoteDirName);

            // Get the dirList before the WriteLine in order to avoid writing an empty newline in case of exceptions
            string dirList = client.GetDirectoryListUnparsed(remoteDirName);
            Console.WriteLine();
            Console.WriteLine(dirList);
        }

        private static bool ValidateTestServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            bool certOk = false;

            if (sslPolicyErrors == SslPolicyErrors.None)
                certOk = true;
            else
            {
                Console.Error.WriteLine();
                
                if((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) > 0)
                    Console.Error.WriteLine("WARNING: SSL/TLS remote certificate chain errors");

                if((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) > 0)
                    Console.Error.WriteLine("WARNING: SSL/TLS remote certificate name mismatch");

                if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) > 0)
                    Console.Error.WriteLine("WARNING: SSL/TLS remote certificate not available");                

                if (options.sslInvalidServerCertHandling == EInvalidSslCertificateHandling.Accept)
                    certOk = true;
            }

            if (!certOk || options.verbose)
            {
                Console.WriteLine();
                Console.WriteLine("SSL/TLS Server certificate details:");
                Console.WriteLine();
                Console.WriteLine(Utility.GetCertificateInfo(certificate));
            }

            if (!certOk && options.sslInvalidServerCertHandling == EInvalidSslCertificateHandling.Prompt)
            {                
                certOk = Utility.ConsoleConfirm("Accept invalid server certificate? (Y/N)");                
            }

            return certOk;
        }

        private static void CheckPassword()
        {
            if (options.userName != null && options.password == null)
            {
                Console.WriteLine();
                Console.Write("Password: ");
                options.password = Utility.ReadConsolePassword();
                Console.WriteLine();
            }
        }

        private static void TransferCallback(FTPSClient sender, ETransferActions action, string localObjectName, string remoteObjectName, ulong fileTransmittedBytes, ulong? fileTransferSize, ref bool cancel)
        {
            switch (action)
            {
                case ETransferActions.FileDownloaded:
                case ETransferActions.FileUploaded:
                    OnFileTransferCompleted(fileTransmittedBytes, fileTransferSize);                    
                    break;
                case ETransferActions.FileDownloadingStatus:
                case ETransferActions.FileUploadingStatus:
                    OnFileTransferStatus(action, localObjectName, remoteObjectName, fileTransmittedBytes, fileTransferSize);
                    break;
                case ETransferActions.RemoteDirectoryCreated:
                    if (options.verbose)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Remote directory created: " + remoteObjectName);                        
                    }
                    break;
                case ETransferActions.LocalDirectoryCreated:
                    if (options.verbose)
                    {
                        Console.WriteLine();
                        Console.WriteLine("Local directory created: " + localObjectName);                        
                    }
                    break;
            }
        }

        private static void OnFileTransferStatus(ETransferActions action, string localObjectName, string remoteObjectName, ulong fileTransmittedBytes, ulong? fileTransferSize)
        {
            if (fileTransmittedBytes == 0)
            {
                // Download / upload start

                watch.Reset();
                watch.Start();

                lastCharPos = 0;

                Console.WriteLine();

                if (action == ETransferActions.FileDownloadingStatus)
                {
                    Console.WriteLine("Source (remote): " + remoteObjectName);
                    Console.WriteLine("Dest (local): " + localObjectName);
                }
                else
                {
                    Console.WriteLine("Source (local): " + localObjectName);
                    Console.WriteLine("Dest (remote): " + remoteObjectName);
                }

                Console.Write("File Size: ");
                if (fileTransferSize != null)
                {
                    Console.WriteLine(fileTransferSize.Value.ToString("N0") + " Byte");
                    Console.WriteLine();
                    Console.WriteLine("0%".PadRight(consoleFormatWidth - 4, ' ') + "100%");
                }
                else
                    Console.WriteLine("Unknown");
            }
            else if (fileTransferSize != null)
            {
                // Download / upload progress

                int charPos = (int)(fileTransmittedBytes * (ulong)consoleFormatWidth / fileTransferSize);

                if (charPos - lastCharPos > 0)
                {
                    Console.Write(new String('.', charPos - lastCharPos));
                    lastCharPos = charPos;
                }
            }
        }

        private static void OnFileTransferCompleted(ulong fileTransmittedBytes, ulong? fileTransferSize)
        {
            watch.Stop();

            filesTrasferredCount++;

            if (fileTransferSize != null)
            {
                Console.WriteLine();

                if (fileTransferSize != fileTransmittedBytes)
                {
                    Console.Error.WriteLine("WARNING: Declared transfer file size ({0:N0}) differs from the transferred bytes count ({1:N0})",
                                      fileTransferSize.Value, fileTransmittedBytes);                    
                }
            }

            double kBs = 0;
            if (watch.ElapsedMilliseconds > 0)
                kBs = fileTransmittedBytes / 1.024D / watch.ElapsedMilliseconds;

            Console.WriteLine("Elapsed time: " + Utility.FormatTimeSpan(watch.Elapsed) + " - Average rate: " + kBs.ToString("N02") + " KB/s");
        }
    }
}
