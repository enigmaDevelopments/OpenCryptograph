using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenCryptograph
{
    public class Key
    {
        private readonly ulong privateKey;
        public readonly ulong publicKey;
        public Key()
        {
            Random random = new Random(Environment.TickCount);
            privateKey = (ulong)random.NextInt64(long.MinValue,long.MaxValue);

        }
    }
}
