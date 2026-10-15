using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

if (args.Length != 3) throw new ArgumentException("Usage: CertificateBuilder <pfx> <cer> <password>");
using var rsa = RSA.Create(2048);
var request = new CertificateRequest("CN=B7B53B09-651D-4171-90BE-4E9E1F5738BA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(2));
File.WriteAllBytes(args[0], certificate.Export(X509ContentType.Pfx, args[2]));
File.WriteAllBytes(args[1], certificate.Export(X509ContentType.Cert));
