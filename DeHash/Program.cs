using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using System.Collections.Generic;
using System.Linq;

public class Sha512Cracker
{
    private static readonly string[] targetHashes = {
        "67705692cb50fbb6921e86e0429b744bbf06cd345eae02ae471b961b1fac2cf413af10eba03cc3e0a66ae05f305c7cd5172208245c7f6e8a1446bb0c5dbc8afd",
        "0678e4bde9816012477bc96e70cc7e5b419b206af07279ff88a564d8744a54ffb5c8092df53ae75c5d8a0445e85bf9bccb927bd34b2f373a90948e2c7d856808",
        "2ce1c01d6ba106e375a8fd665d9323abadd18d33e8930aadc3a8166f9491fbb67d223d5a5174de25b99b39f54eab38623e981271f55465b354a5e296d36a8354",
        "0ca82ffc3b1f17064ad1ebbae0fec9db55b1bb727bbf9a4f8cfaa8d6485063baf31257d120205699a26ac467d50e8eb872c7acbfd9c728e4c68d5b7506800ed3",
        "c8a6cd3dbcce9cde5a291d91f14c2f1fd4c3961c80b5f847a10c944fdfae2ee52b0fd31e839bbf84c90da265ff7e8d8620a4508561c2cb1d9d050119b125a2ee",
"7a206b004e32d2e96663da86a1dda28c121736cb4bec418a184245cadcff8356050d8213eaf412edff5d47b9f1976319f5f29baec8d1a2343b7f48a844dea547",
"54c69aaf89f7fcc483cf0397e6ca8aee61cbd1f39c6fd68680196762dcc017b229889b1976d64baebc4956ade5119af642cfc0df263b108795029ea4c7921523",
"ccd43b4a8b905cc4d6ff11b78f85323d882b08dc08193eecde3162f0a95b129068a6c331821cdc228372bae63846d7324e249e716ebd9d8c8f743fed2ba50736",
"349c82f534142da76321aeb46c2739310853bc20465c118bdd3aeeec21b9e35f1c0f07ef8fc7cac5589a7b239bc737c5ea5bc62d51ee9f3ac4cd1de2592ae9ad",
"62b93fdfb944a5cfd6af30b250ca97a7b7c47561012aea9c049ef241ff78e173ce4c76f3e3d3e43d3f4844e37e7313ebdbe9f2ff636880f1ebd75353e8a55965",
"164719442f78b7222e29d3f31ec29acab6b90c99f966583a43c14313e790e130406a3ed3b3764cf44108ace4f7fda561dca45f7f640e94122b0dc3eed4d8c3bb",
"4fcc429d07b98352e4a2877f236b73c8ff2a62b825a54a0c82357f2c09f3caef32c53c684623c2a8631b65d1e33f1f36d7bf3aca6c474351ed1c48811cc4550c",
"6e9564685eb16c0c516ff1210dc6e94dc183faf1a1026116fccddb4d215e8df8eb82440d2bbbf4ee5d605edef87db7ce602eeb0bf0b8000b063753b8996e2ae3",
"fd54a8c44341a054107c8b61e0f83e7dd54a21a6de26cb5f165c7e24887a6766c0ee8c31e55c123793b18d2ab7202d135455905b588cee8796d42361cb2804cd",
"3aaa72ccf086c65676afa0142106f9f50c2d40a4e89dc850201bb7d829e969dcce38e5050671a56cf2f3f74c56756842ac3f9a2f69b7631dd9966dad9bffe8a9",
"ad67f180e80a6cdce0c8b4f97e999ef6404763cd0ab17dc19bd3acda45716b35f4cfd8eafd2e07596a858857caa36b0e395bfa6b55854a16750085b9c8ea06d8",
"b5eae3c46182a31d9c32c7d469c2e2725a4506230116df86d1d3998705cf2190974147c4e6f01e9dc5b460d473746cf007b81a7f4a38c512562cc384ce7f7fa4",
"38bfebbfafaec1f1b19504bcdbd513b240cc5b7333e8be722883a471f6e6145df7ddcb6b83bae337eb1f7deca06dd0fb2573d7e6d8f74ad3240aed807f07039a",
"0042605631d108a4a55b6bf6616c0f28b100b0695f90a950aeddb04378188ffd450c215c59d1797030a8f432e63359623cfdfecb81eae551657e21d64d2ecde7",
"ed451f8b3026c6236d9282ceaa6b0cba69be4c80040430fb0b65e32119bdc2bfc8debdfbe530711c94550c3b947c3fab5eac0e079cf690b0b5fd6b53bb6631c9",
"af52cba7ccb488166d3c67d935f239339744e294da8e573ae97306e1f9c20514d9a2d3bd7ccb718b6f389ede297645bc25a502174b8b2120a1f5b743dd04301d"
    };
    private static string charset = "0123456789abcdefghijklmnopqrstuvwxyz";
    private static int passwordLength = 7;
    private static HashSet<string> foundHashes = new HashSet<string>();

    private static string CalculateSha512(string input)
    {
        Sha512Digest digest = new Sha512Digest();
        byte[] inputBytes = Encoding.UTF8.GetBytes(input);
        digest.BlockUpdate(inputBytes, 0, inputBytes.Length);
        byte[] hashBytes = new byte[digest.GetDigestSize()];
        digest.DoFinal(hashBytes, 0);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hashBytes.Length; i++)
        {
            sb.Append(hashBytes[i].ToString("x2"));
        }
        return sb.ToString();
    }

    private static void Crack(long start, long end, string[] hashesToCrack)
    {
        long charsetSize = charset.Length;

        for (long i = start; i < end; i++)
        {
            //Строка неизменяемая, а вот стринг билдер -- вполне себе
            StringBuilder password = new StringBuilder();
            long temp = i;
            for (int j = 0; j < passwordLength; j++)
            {
                password.Append(charset[(int)(temp % charsetSize)]);
                temp /= charsetSize;
            }
            //Заккоментировать, если зеркальный порядок символов не принципиален
            char[] charArray = password.ToString().ToCharArray();
            Array.Reverse(charArray);

            string finalPassword = new string(charArray);

            string currentHash = CalculateSha512(finalPassword);
            foreach (string targetHash in hashesToCrack)
            {
                if (!foundHashes.Contains(targetHash) && currentHash == targetHash)
                {
                    Console.WriteLine($"Password found for {targetHash}: {finalPassword}");
                    foundHashes.Add(targetHash);
                    break; // Остановка перебора хэшей
                }
            }

            if (foundHashes.Count == hashesToCrack.Length)
            {
                return; // Все хжши найдены
            }
        }
    }

    public static void Main(string[] args)
    {
        long totalCombinations = (long)Math.Pow(charset.Length, passwordLength);
        int numThreads = Environment.ProcessorCount;
        long chunkSize = totalCombinations / numThreads;

        Task[] tasks = new Task[numThreads];
        for (int i = 0; i < numThreads; i++)
        {
            long start = i * chunkSize;
            long end = (i == numThreads - 1) ? totalCombinations : start + chunkSize;
            tasks[i] = Task.Run(() => Crack(start, end, targetHashes));
        }

        Task.WaitAll(tasks);

        if (foundHashes.Count < targetHashes.Length)
        {
            foreach (var hash in targetHashes.Where(h => !foundHashes.Contains(h)))
            {
                Console.WriteLine($"Password not found for {hash}.");
            }
        }
    }
}