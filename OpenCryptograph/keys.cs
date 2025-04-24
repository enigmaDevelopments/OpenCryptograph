using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpenCryptograph
{
    public class Key
    {
        private ulong privateKey;
        private ulong _publicKey;
        public ulong publicKey
        {
            get
            {
                return _publicKey;
            }
        }
        public Key()
        {
            Random random = new Random(Environment.TickCount);
            privateKey = (ulong)random.NextInt64();
            privateKey |= (ulong)(random.Next(Environment.TickCount)&1) << 63;

        }
    }
}
