using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using System.Text;
using System.Security.Cryptography.Xml;
using Ionic.Zip;
using System.Security.Cryptography.X509Certificates;
using System.Configuration;

namespace Fatca.Core
{
    public class FatcaGenerator
    {

        public string GenerateFatcaPackets(string sendingCompanyIN, string parentCompanyIN, String destinationIN, string soapXml, string outputDirectory)
        {
            bool isExists = System.IO.Directory.Exists(@outputDirectory + "Output\\" + sendingCompanyIN);

            if (!isExists)
                System.IO.Directory.CreateDirectory(@outputDirectory + "Output\\" + sendingCompanyIN);

            System.IO.File.WriteAllText(@outputDirectory + "Output\\" + sendingCompanyIN + "\\"+parentCompanyIN + "_Payload.xml", soapXml);

            //create directory for signed
            isExists = System.IO.Directory.Exists(@outputDirectory + "Signed\\" + sendingCompanyIN);

            if (!isExists)
                System.IO.Directory.CreateDirectory(@outputDirectory + "Signed\\" + sendingCompanyIN);

            //create directory for zipped
            isExists = System.IO.Directory.Exists(@outputDirectory + "Zipped\\" + sendingCompanyIN);

            if (!isExists)
                System.IO.Directory.CreateDirectory(@outputDirectory + "Zipped\\" + sendingCompanyIN);

            //create directory for Keys
            isExists = System.IO.Directory.Exists(@outputDirectory + "Keys\\" + parentCompanyIN);

            if (!isExists)
                System.IO.Directory.CreateDirectory(@outputDirectory + "Keys\\" + sendingCompanyIN);

            //create directory for Encrypted
            isExists = System.IO.Directory.Exists(@outputDirectory + "Encrypted\\" + sendingCompanyIN);

            if (!isExists)
                System.IO.Directory.CreateDirectory(@outputDirectory + "Encrypted\\" + sendingCompanyIN);

           
            //create directory for DataPackets
            isExists = System.IO.Directory.Exists(@outputDirectory + "DataPacket\\" + sendingCompanyIN);

            if (!isExists)
                System.IO.Directory.CreateDirectory(@outputDirectory + "DataPacket\\" + sendingCompanyIN);


            generateRSA(@outputDirectory + "Output\\" + sendingCompanyIN + "\\" + parentCompanyIN + "_Payload.xml");
            zipFiles(@outputDirectory + "Signed\\" + sendingCompanyIN + "\\" + parentCompanyIN + "_Payload.xml");
            string rawPassword = EncryptFileAndReturnEncryptedKey(@outputDirectory + "Zipped\\" + sendingCompanyIN + "\\" + parentCompanyIN + "_Payload.zip");

            EncryptKeyInAES(rawPassword, @outputDirectory + "Keys\\" + parentCompanyIN, sendingCompanyIN, parentCompanyIN);

            return GenerateDataPacket(@outputDirectory + "DataPacket\\" + sendingCompanyIN, sendingCompanyIN, destinationIN, parentCompanyIN);
        }

        private void EncryptKeyInAES(string key, string saveDirectory, string companyGIIN, string parentGIIN)
        {


            bool isExists = System.IO.Directory.Exists(saveDirectory);

            if (!isExists)
                System.IO.Directory.CreateDirectory(saveDirectory);

            string certFile = @ConfigurationManager.AppSettings["CertFileLocation"];

            string cert = System.IO.File.ReadAllText(@certFile);

            byte[] encryptedKeyBytes = RSAEncrypt(key, cert, true);
            System.IO.File.WriteAllBytes(saveDirectory + "\\" + "000000.00000.TA.840_Key", encryptedKeyBytes);


        }

        private string GenerateDataPacket(string saveDirectory, string companyGIIN, String receivingGIIN, string parentGIIN)
        {
            //copy from embedded resource into MetaData Path


            String metadataPath = saveDirectory.Replace("DataPacket", "MetaData") + "\\" + parentGIIN + "_MetaData.xml";
            metadataPath = metadataPath.Replace("\\" + companyGIIN + "\\" + parentGIIN, "\\" + parentGIIN);
            
           

            String receiveridPath = metadataPath.Replace("MetaData", "Keys") + "\\" + receivingGIIN + "_Key";
            receiveridPath = receiveridPath.Replace("_Keys.xml", "");
            String senderIdPath = saveDirectory.Replace("DataPacket", "Encrypted") + "_Payload";
            senderIdPath = senderIdPath.Replace(companyGIIN + "_Payload", companyGIIN + "\\" + parentGIIN + "_Payload");
            metadataPath = metadataPath.Replace("\\" + companyGIIN + "\\" + companyGIIN, "\\" + companyGIIN);

            bool isExists = System.IO.Directory.Exists(saveDirectory);

            if (!isExists)
                System.IO.Directory.CreateDirectory(saveDirectory);

            string finalpath = "";
            using (ZipFile zip = new ZipFile())
            {
                zip.AddFile(metadataPath, "");
                zip.AddFile(receiveridPath, "");
                zip.AddFile(senderIdPath, "");
                //yyyy-MM-dd'T'HH:mm:ss'Z'
                finalpath = saveDirectory + "\\" + DateTime.Now.ToString("yyyyMMdd'T'HHmmssfff'Z'_") + parentGIIN + ".zip";
                zip.Save(finalpath);

            }


            return finalpath;


        }

        private void zipFiles(string ZipFilePath)
        {
            using (ZipFile zip = new ZipFile())
            {
                zip.AddFile(ZipFilePath);
                ZipFilePath = ZipFilePath.Replace("Signed", "Zipped");
                ZipFilePath = ZipFilePath.Replace(".xml", ".zip");
                zip.Save(ZipFilePath);
            }


        }

        public String EncryptFileAndReturnEncryptedKey(String EncryptPath)
        {
            string file = EncryptPath;
            string password = RandomString(32);// DateTime.Now.ToString("yyyyMMddHHmmssffff");

            byte[] bytesToBeEncrypted = System.IO.File.ReadAllBytes(file);
            String stringToBeEncrypted = System.IO.File.ReadAllText(file);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

            // Hash the password with SHA256
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesEncrypted = AES_Encrypt(stringToBeEncrypted, null, password, false);

            EncryptPath = EncryptPath.Replace("Zipped", "Encrypted");
            EncryptPath = EncryptPath.Replace(".zip", "");
            System.IO.File.WriteAllBytes(EncryptPath, bytesEncrypted);

            return password;
        }

        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(passwordBytes, null, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }

            return encryptedBytes;
        }


        private byte[] AES_Encrypt(string text, string AesIV, string AesKey, bool isKeyEncryption)
        {
            // AesCryptoServiceProvider
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            aes.BlockSize = 128;
            if (isKeyEncryption)
            {
                aes.KeySize = 2048;
            }
            else
            {
                aes.KeySize = 256;
            }
            //aes.IV = Encoding.UTF8.GetBytes(AesIV);
            aes.Key = Encoding.UTF8.GetBytes(AesKey);
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;

            // Convert string to byte array
            byte[] src = Encoding.Unicode.GetBytes(text);

            // encryption
            using (ICryptoTransform encrypt = aes.CreateEncryptor())
            {
                byte[] dest = encrypt.TransformFinalBlock(src, 0, src.Length);

                // Convert byte array to Base64 strings
                return dest;
            }
        }


        static public byte[] RSAEncrypt(string stringToBeEncrypted, string Key, bool DoOAEPPadding)
        {
            try
            {

                byte[] DataToEncrypt = Encoding.Unicode.GetBytes(stringToBeEncrypted);
                String publicKey = VerifyCertificate(Encoding.Unicode.GetBytes(Key), null);
                byte[] publicKeyByte = Encoding.Unicode.GetBytes(publicKey);
                byte[] Exponent = { 1, 0, 1 };
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider. 
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(2048))
                {



                    RSAParameters RSAKeyInfo = new RSAParameters();
                    RSAKeyInfo.Modulus = publicKeyByte;
                    RSAKeyInfo.Exponent = Exponent;


                    //Encrypt the passed byte array and specify OAEP padding.   
                    //OAEP padding is only available on Microsoft Windows XP or 
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, false);
                }
                return encryptedData;
            }

            //Catch and display a CryptographicException   
            //to the console. 
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }

        }

        //public static byte[] Encrypt(byte[] data, int keySize, string publicKeyXml)
        //{
        //    if (data == null || data.Length == 0) throw new ArgumentException("Data are empty", "data");
        //    int maxLength = GetMaxDataLength(keySize);
        //    if (data.Length > maxLength) throw new ArgumentException(String.Format("Maximum data length is {0}", maxLength), "data");
        //    if (!IsKeySizeValid(keySize)) throw new ArgumentException("Key size is not valid", "keySize");
        //    if (String.IsNullOrEmpty(publicKeyXml)) throw new ArgumentException("Key is null or empty", "publicKeyXml");

        //    using (var provider = new RSACryptoServiceProvider(keySize))
        //    {
        //        provider.FromXmlString(publicKeyXml);
        //        return provider.Encrypt(data, _optimalAsymmetricEncryptionPadding);
        //    }
        //}


        public static bool IsKeySizeValid(int keySize)
        {
            return keySize >= 384 &&
                    keySize <= 16384 &&
                    keySize % 8 == 0;
        }
        //public static int GetMaxDataLength(int keySize)
        //{
        //    if (_optimalAsymmetricEncryptionPadding)
        //    {
        //        return ((keySize - 384) / 8) + 7;
        //    }
        //    return ((keySize - 384) / 8) + 37;
        //}

        static String VerifyCertificate(byte[] primaryCertificate, IEnumerable<byte[]> additionalCertificates)
        {
            var chain = new X509Chain();
            //foreach (var cert in additionalCertificates.Select(x => new X509Certificate2(x)))
            //{
            //    chain.ChainPolicy.ExtraStore.Add(cert);
            //}

            // You can alter how the chain is built/validated.
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;

            // Do the validation.

            var primaryCert = new X509Certificate2(primaryCertificate);


            return primaryCert.GetPublicKeyString();
            //return chain.Build(primaryCert);
        }
        private string RandomString(int size)
        {
            StringBuilder builder = new StringBuilder();
            Random random = new Random();
            char ch;
            for (int i = 0; i < size; i++)
            {
                ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 65)));
                builder.Append(ch);
            }

            return builder.ToString();
        }

        private void generateRSA(string payLoadPath)
        {
            string certFile = @ConfigurationManager.AppSettings["CertFileLocation"];

            string CAcert = System.IO.File.ReadAllText(@certFile);
            String cert = VerifyCertificate(Encoding.Unicode.GetBytes(CAcert), null);
            byte[] data = Encoding.ASCII.GetBytes(cert);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
            {

                byte[] signature = rsa.SignData(data, "SHA256");


                RSA rsakey = RSA.Create();
                rsa.ImportParameters(rsa.ExportParameters(true));
                XmlDocument xmlDoc = new XmlDocument();

                xmlDoc.Load(payLoadPath);

                SignXml(xmlDoc, rsakey);
                string signedOutputPath = payLoadPath.Replace("Output", "Signed");

                System.IO.File.WriteAllText(signedOutputPath, xmlDoc.OuterXml);



            }
        }

        // Sign an XML file.  
        // This document cannot be verified unless the verifying  
        // code has the key with which it was signed. 
        public void SignXml(XmlDocument xmlDoc, RSA Key)
        {
            // Check arguments. 
            if (xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            if (Key == null)
                throw new ArgumentException("Key");

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = Key;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            // XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            // reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));

        }
    }
}
