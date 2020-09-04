using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using NSec.Cryptography;
using TextCopy;
using static System.Enum;

namespace cage
{
    internal class Program
    {
        private const KeyBlobFormat Pub = KeyBlobFormat.RawPublicKey;
        private const KeyBlobFormat Priv = KeyBlobFormat.RawPrivateKey;
        private const KeyBlobFormat Sym = KeyBlobFormat.RawSymmetricKey;
        private static string _privatekey;
        private static readonly string _privatekeyheader = "cageprv1";
        private static readonly string _publickeyheader = "cagepub1";
        private static readonly AeadAlgorithm Aead = AeadAlgorithm.ChaCha20Poly1305;

        private static void Main()
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.SetIn(new StreamReader(Console.OpenStandardInput(new byte[4096].Length), Console.InputEncoding,
                false, new byte[4096].Length));
            Console.WriteLine(StartupTests(51) ? "Passed all startup tests!" : "Failed startup tests!");
            Console.ForegroundColor = ConsoleColor.White;
            var showMenu = true;
            while (showMenu) showMenu = MainMenu();
        }

        private static bool MainMenu()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(
                "\r\nChoose an option:\r\n1) Generate key-pair\r\n2) Encrypt\r\n3) Decrypt\r\n4) Run longer tests\r\n5) Generate vanity keypair\r\n6) Exit\r\nSelect an option: ");
            Console.ForegroundColor = ConsoleColor.White;
            switch (Console.ReadLine())
            {
                case "1":
                    GenerateKeypair();
                    return true;
                case "2":
                    Encrypt();
                    return true;
                case "3":
                    Decrypt();
                    return true;
                case "4":
                    Tests();
                    return true;
                case "5":
                    GenerateVanityKeypair();
                    return true;
                case "6": return false;
                default: return true;
            }
        }

        private static void Tests()
        {
            Console.WriteLine("Performing tests...");
            foreach (var i in Enumerable.Range(0, 10000))
            {
                var key = Key.Create(KeyAgreementAlgorithm.X25519,
                    new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextExport});
                var key2 = Key.Create(KeyAgreementAlgorithm.X25519,
                    new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextExport});
                var test1 = Convert.ToBase64String(SharedKey(key.Export(Pub), key2.Export(Priv))
                                .Export(KeyBlobFormat.NSecSymmetricKey)) ==
                            Convert.ToBase64String(SharedKey(key2.Export(Pub), key.Export(Priv))
                                .Export(KeyBlobFormat.NSecSymmetricKey));
                var encdata = Aead.Encrypt(SharedKey(key.Export(Pub), key2.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, Encoding.UTF8.GetBytes("test2"));
                var encdata2 = Aead.Encrypt(SharedKey(key2.Export(Pub), key.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, Encoding.UTF8.GetBytes("test2"));
                var test2 = Convert.ToBase64String(encdata) == Convert.ToBase64String(encdata2);
                var dec = Aead.Decrypt(SharedKey(key.Export(Pub), key2.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, encdata, out var decdata);
                var dec2 = Aead.Decrypt(SharedKey(key2.Export(Pub), key.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, encdata, out var decdata2);
                var test3 = dec && dec2;
                var test4 = Convert.ToBase64String(decdata ?? throw new InvalidOperationException()) ==
                            Convert.ToBase64String(decdata2 ?? throw new InvalidOperationException());
                if (test1 && test2 && test3 && test4)
                {
                    if (i % 100 == 0) Console.WriteLine($"Passed {i}");
                }
                else
                {
                    Console.WriteLine(
                        $"Failed a test at {i} out of 10000. Test 1 (Key agreement): {test1} \r\nTest 2 (Encrypting with same key): {test2}\r\nTest 3 (Testing if decryption passes): {test3}\r\nTest 4(Testing if decrypted data is identical: {test4}");
                    return;
                }
            }
        }

        private static bool StartupTests(int count)
        {
            Console.WriteLine("Performing tests...");
            var stopwatch = new Stopwatch();
            stopwatch.Start();
            foreach (var i in Enumerable.Range(0, count))
            {
                var key = Key.Create(KeyAgreementAlgorithm.X25519,
                    new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextExport});
                var key2 = Key.Create(KeyAgreementAlgorithm.X25519,
                    new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextExport});
                var test1 = Convert.ToBase64String(SharedKey(key.Export(Pub), key2.Export(Priv))
                                .Export(KeyBlobFormat.NSecSymmetricKey)) ==
                            Convert.ToBase64String(SharedKey(key2.Export(Pub), key.Export(Priv))
                                .Export(KeyBlobFormat.NSecSymmetricKey));
                var encdata = Aead.Encrypt(SharedKey(key.Export(Pub), key2.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, Encoding.UTF8.GetBytes("test2"));
                var encdata2 = Aead.Encrypt(SharedKey(key2.Export(Pub), key.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, Encoding.UTF8.GetBytes("test2"));
                var test2 = Convert.ToBase64String(encdata) == Convert.ToBase64String(encdata2);
                var dec = Aead.Decrypt(SharedKey(key.Export(Pub), key2.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, encdata, out var decdata);
                var dec2 = Aead.Decrypt(SharedKey(key2.Export(Pub), key.Export(Priv)), new Nonce(0, 12),
                    ReadOnlySpan<byte>.Empty, encdata, out var decdata2);
                var test3 = dec && dec2;
                var test4 = Convert.ToBase64String(decdata ?? throw new InvalidOperationException()) ==
                            Convert.ToBase64String(decdata2 ?? throw new InvalidOperationException());
                if (test1 && test2 && test3 && test4)
                {
                    Console.Write($"\rPassed {i}");
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
                else
                {
                    Console.WriteLine(
                        $"Failed test {i} out of {count}. Test 1 (Key agreement): {test1} \r\nTest 2 (Encrypting with same key): {test2}\r\nTest 3 (Testing if decryption passes): " +
                        $"{test3}\r\nTest 4(Testing if decrypted data is identical: {test4}");
                    return false;
                }
            }

            stopwatch.Stop();
            Console.Write($" {stopwatch.ElapsedMilliseconds} ms elapsed\r\n");
            return true;
        }

        private static void GenerateKeypair()
        {
            var key = Key.Create(KeyAgreementAlgorithm.X25519,
                new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving});
            Console.Write("Your public key: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{_publickeyheader}{Convert.ToBase64String(key.Export(Pub))} (copied to clipboard)");
            Console.ForegroundColor = ConsoleColor.White;
            ClipboardService.SetText(_publickeyheader + Convert.ToBase64String(key.Export(Pub)));
            var privkey = Convert.ToBase64String(key.Export(Priv));
            Console.Write("\r\nYour private key: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write($"{_privatekeyheader}{privkey} (will be saved in memory until this application is closed)");
            _privatekey = privkey;
            Console.ForegroundColor = ConsoleColor.White;
        }

        private static void GenerateVanityKeypair()
        {
            Console.WriteLine("What do you want your public key to start with?");
            var vanity = Console.ReadLine();
            var i = 0;
            while (true)
            {
                i++;

                var key = Key.Create(KeyAgreementAlgorithm.X25519,
                    new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving});
                if (Convert.ToBase64String(key.Export(Pub)).ToLower()
                    .StartsWith(vanity ?? throw new InvalidOperationException()))
                {
                    Console.Write("\r\nYour public key: ");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write($"{_publickeyheader}{Convert.ToBase64String(key.Export(Pub))} (copied to clipboard)");
                    Console.ForegroundColor = ConsoleColor.White;
                    ClipboardService.SetText(_publickeyheader + Convert.ToBase64String(key.Export(Pub)));
                    var privkey = Convert.ToBase64String(key.Export(Priv));
                    Console.Write("\r\nYour private key: ");
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.Write(
                        $"{_privatekeyheader}{privkey} (will be saved in memory until this application is closed)");
                    _privatekey = privkey;
                    Console.ForegroundColor = ConsoleColor.White;
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    return;
                }

                Console.Write($"\rUp to {i}    ");
                if (i % 100 != 0) continue;
                GC.Collect();
                GC.WaitForPendingFinalizers();
                Console.ForegroundColor = RandomConsoleColor();
            }
        }

        private static ConsoleColor RandomConsoleColor()
        {
            return (ConsoleColor) GetValues(typeof(ConsoleColor))
                .GetValue(new Random().Next(GetValues(typeof(ConsoleColor)).Length));
        }

        private static void Encrypt()
        {
            Console.WriteLine("Paste in the public key:");
            var publickey = Console.ReadLine();
            if (publickey != null && !publickey.StartsWith(_publickeyheader))
            {
                Console.WriteLine("Invalid public key!");
                if (publickey.StartsWith(_privatekeyheader)) Console.WriteLine("That is a private key!");
                return;
            }

            publickey = publickey?.Replace(_publickeyheader, "");
            Console.WriteLine("Paste in the text you want to encrypt:");
            var plaintext = Console.ReadLine();
            try
            {
                var key = Key.Create(KeyAgreementAlgorithm.X25519,
                    new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving});
                var sharedkey = SharedKey(Convert.FromBase64String(publickey ?? throw new InvalidOperationException()),
                    key.Export(Priv));
                var encrypt = Aead.Encrypt(sharedkey, new Nonce(0, 12), ReadOnlySpan<byte>.Empty,
                    Encoding.UTF8.GetBytes(plaintext ?? throw new InvalidOperationException()));
                var output = Convert.ToBase64String(encrypt) + ":" + Convert.ToBase64String(key.Export(Pub));
                Console.WriteLine(Convert.ToBase64String(sharedkey.Export(Sym)));
                Console.Write("Your cipher-text is: ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"{output}");
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("\r\nCopied cipher-text");
                ClipboardService.SetText(output);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        private static void Decrypt()
        {
            if (_privatekey == null)
            {
                Console.WriteLine("Paste in the private key:");
                var privatekeyinput = Console.ReadLine();
                if (privatekeyinput != null && privatekeyinput.Contains(_privatekeyheader))
                    _privatekey = privatekeyinput.Replace(_privatekeyheader, "");
                else Console.WriteLine("Invalid private key!");
            }
            else
            {
                Console.WriteLine("Loaded private key from memory!");
            }

            Console.WriteLine("Paste in the cipher-text:");
            var ciphertext = Console.ReadLine();
            try
            {
                Console.WriteLine(Aead.Decrypt(
                    SharedKey(
                        Convert.FromBase64String(ciphertext?.Split(":")[1] ?? throw new InvalidOperationException()),
                        Convert.FromBase64String(_privatekey ?? throw new InvalidOperationException())),
                    new Nonce(0, 12), ReadOnlySpan<byte>.Empty, Convert.FromBase64String(ciphertext.Split(":")[0]),
                    out var output));
                Console.WriteLine(Convert.ToBase64String(SharedKey(Convert.FromBase64String(ciphertext.Split(":")[1]),
                    Convert.FromBase64String(_privatekey)).Export(Sym)));

                var plaintext = Encoding.UTF8.GetString(output ?? throw new InvalidOperationException());
                Console.Write("Your plain-text is: ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"{plaintext}");
                Console.ForegroundColor = ConsoleColor.White;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public static Key SharedKey(byte[] pubkey, byte[] privkey)
        {
            return KeyDerivationAlgorithm.HkdfSha512.DeriveKey(KeyAgreementAlgorithm.X25519.Agree(
                    Key.Import(KeyAgreementAlgorithm.X25519, privkey, Priv),
                    PublicKey.Import(KeyAgreementAlgorithm.X25519, pubkey, Pub))!, ReadOnlySpan<byte>.Empty,
                ReadOnlySpan<byte>.Empty, Aead,
                new KeyCreationParameters {ExportPolicy = KeyExportPolicies.AllowPlaintextArchiving});
        }
    }
}