using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

internal class Program
{
    static string key;
    static string name;
    static string hash;

    public static void Main(string[] args)
    {
        SaveCertificate("https://sap-dev.uxm-sap-internal.com");
    }
    /// <summary>
    /// Get and write certificate from URL into file in path
    /// </summary>
    /// <param name="_URL">URL of website with certficate</param>
    /// <param name="_path">Path where you want to store certificate</param>
    private static void SaveCertificate(string url)
    {

        var request = (HttpWebRequest)WebRequest.Create(url);
        request.AllowAutoRedirect = false;
        request.ServerCertificateValidationCallback = GetCAPublicKey;

        HttpWebResponse response = (HttpWebResponse)request.GetResponse();
        response.Close();

        Console.WriteLine($"name = {name}\n" +
            $"key = {key}\n" +
            $"hash = {hash}\n" +
            $"url = {url}");
    }

    private static bool GetCAPublicKey(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        //keep overwriting til we get to the last one
        foreach (var cer in chain.ChainElements)
        {
            name = cer.Certificate.FriendlyName;
            key = Convert.ToBase64String(cer.Certificate.GetPublicKey());
            hash = GetPublicKeyPinningHash(cer.Certificate);
        }

        return true;
    }

    static String GetPublicKeyPinningHash(X509Certificate2 x509Cert)
    {
        //Public Domain: No attribution required
        //Get the SubjectPublicKeyInfo member of the certificate
        Byte[] subjectPublicKeyInfo = GetSubjectPublicKeyInfoRaw(x509Cert);

        //Take the SHA2-256 hash of the DER ASN.1 encoded value
        Byte[] digest;
        using (var sha2 = new SHA256Managed())
        {
            digest = sha2.ComputeHash(subjectPublicKeyInfo);
        }

        //Convert hash to base64
        String hash = Convert.ToBase64String(digest);

        return hash;
    }


    static Byte[] GetSubjectPublicKeyInfoRaw(X509Certificate2 x509Cert)
    {
        //Public Domain: No attribution required
        Byte[] rawCert = x509Cert.GetRawCertData();

        /*
         Certificate is, by definition:

            Certificate  ::=  SEQUENCE  {
                tbsCertificate       TBSCertificate,
                signatureAlgorithm   AlgorithmIdentifier,
                signatureValue       BIT STRING  
            }

           TBSCertificate  ::=  SEQUENCE  {
                version         [0]  EXPLICIT Version DEFAULT v1,
                serialNumber         CertificateSerialNumber,
                signature            AlgorithmIdentifier,
                issuer               Name,
                validity             Validity,
                subject              Name,
                subjectPublicKeyInfo SubjectPublicKeyInfo,
                issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
                subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version MUST be v2 or v3
                extensions      [3]  EXPLICIT Extensions       OPTIONAL  -- If present, version MUST be v3
            }

        So we walk to ASN.1 DER tree in order to drill down to the SubjectPublicKeyInfo item
        */
        Byte[] list = AsnNext(ref rawCert, true); //unwrap certificate sequence
        Byte[] tbsCertificate = AsnNext(ref list, false); //get next item; which is tbsCertificate
        list = AsnNext(ref tbsCertificate, true); //unwap tbsCertificate sequence

        Byte[] version = AsnNext(ref list, false); //tbsCertificate.Version
        Byte[] serialNumber = AsnNext(ref list, false); //tbsCertificate.SerialNumber
        Byte[] signature = AsnNext(ref list, false); //tbsCertificate.Signature
        Byte[] issuer = AsnNext(ref list, false); //tbsCertificate.Issuer
        Byte[] validity = AsnNext(ref list, false); //tbsCertificate.Validity
        Byte[] subject = AsnNext(ref list, false); //tbsCertificate.Subject        
        Byte[] subjectPublicKeyInfo = AsnNext(ref list, false); //tbsCertificate.SubjectPublicKeyInfo        

        return subjectPublicKeyInfo;
    }


    static Byte[] AsnNext(ref Byte[] buffer, Boolean unwrap)
    {
        //Public Domain: No attribution required
        Byte[] result;

        if (buffer.Length < 2)
        {
            result = buffer;
            buffer = new Byte[0];
            return result;
        }

        int index = 0;
        Byte entityType = buffer[index];
        index += 1;

        int length = buffer[index];
        index += 1;

        int lengthBytes = 1;
        if (length >= 0x80)
        {
            lengthBytes = length & 0x0F; //low nibble is number of length bytes to follow
            length = 0;

            for (int i = 0; i < lengthBytes; i++)
            {
                length = (length << 8) + (int)buffer[2 + i];
                index += 1;
            }
            lengthBytes++;
        }

        int copyStart;
        int copyLength;
        if (unwrap)
        {
            copyStart = 1 + lengthBytes;
            copyLength = length;
        }
        else
        {
            copyStart = 0;
            copyLength = 1 + lengthBytes + length;
        }
        result = new Byte[copyLength];
        Array.Copy(buffer, copyStart, result, 0, copyLength);

        Byte[] remaining = new Byte[buffer.Length - (copyStart + copyLength)];
        if (remaining.Length > 0)
            Array.Copy(buffer, copyStart + copyLength, remaining, 0, remaining.Length);
        buffer = remaining;

        return result;
    }

}