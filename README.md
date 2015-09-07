# FTPSClient
Extension of Alex's FTPS client recompiled for .net4.5.1 / .net 4.5

Original project: https://ftps.codeplex.com/

Protocols set to:
SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls

Package at:
https://www.nuget.org/packages/AlexFTPSv2

This package was created to address errors encountered while trying to connect to an endpoint that had deprecated the endpoints available in .net 2.0 (sslv3 etc).

The error encountered was: 
* {"A call to SSPI failed, see inner exception."}
* {"The message received was unexpected or badly formatted"}
 
After quite a bit of troubleshooting I determined that the .net 2.0 build target and missing modern SSL protocols was the culprit, as the original library had not been updated since 2011 I decided to get the source, modify and publish.

If the original author would like pull in my changes and republish I'd be happy to provide :)

