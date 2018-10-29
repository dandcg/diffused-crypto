using System;
using System.Linq;
using Diffused.Crypto.Curve;
using Xunit;

namespace Diffused.Crypto.Tests.Curve.Backend.u64
{
    public class UnpackedScalarTests
    {
        // Note: x is 2^253-1 which is slightly larger than the largest scalar produced by
        // this implementation (l-1), and should show there are no overflows for valid scalars
        //
        // x = 14474011154664524427946373126085988481658748083205070504932198000989141204991
        // x = 7237005577332262213973186563042994240801631723825162898930247062703686954002 mod l
        // x = 3057150787695215392275360544382990118917283750546154083604586903220563173085*R mod l in Montgomery form
        public static UnpackedScalar X = new UnpackedScalar(new ulong[]
        {
            0x000fffffffffffff, 0x000fffffffffffff, 0x000fffffffffffff, 0x000fffffffffffff, 0x00001fffffffffff
        });

        /// x^2 = 3078544782642840487852506753550082162405942681916160040940637093560259278169 mod l
        public static UnpackedScalar XX = new UnpackedScalar(new ulong[]
        {
            0x0001668020217559, 0x000531640ffd0ec0, 0x00085fd6f9f38a31, 0x000c268f73bb1cf4, 0x000006ce65046df0
        });

        /// x^2 = 4413052134910308800482070043710297189082115023966588301924965890668401540959*R mod l in Montgomery form
        public static UnpackedScalar XX_MONT = new UnpackedScalar(new ulong[]
        {
            0x000c754eea569a5c, 0x00063b6ed36cb215, 0x0008ffa36bf25886, 0x000e9183614e7543, 0x0000061db6c6f26f
        });

        /// y = 6145104759870991071742105800796537629880401874866217824609283457819451087098
        public static UnpackedScalar Y = new UnpackedScalar(new ulong[]
        {
            0x000b75071e1458fa, 0x000bf9d75e1ecdac, 0x000433d2baf0672b, 0x0005fffcc11fad13, 0x00000d96018bb825
        });

        /// x*y = 36752150652102274958925982391442301741 mod l
        public static UnpackedScalar XY = new UnpackedScalar(new ulong[]
        {
            0x000ee6d76ba7632d, 0x000ed50d71d84e02, 0x00000000001ba634, 0x0000000000000000, 0x0000000000000000
        });

        /// x*y = 658448296334113745583381664921721413881518248721417041768778176391714104386*R mod l in Montgomery form
        public static UnpackedScalar XY_MONT = new UnpackedScalar(new ulong[]
        {
            0x0006d52bf200cfd5, 0x00033fb1d7021570, 0x000f201bc07139d8, 0x0001267e3e49169e, 0x000007b839c00268
        });

        /// a = 2351415481556538453565687241199399922945659411799870114962672658845158063753
        public static UnpackedScalar A = new UnpackedScalar(new ulong[]
        {
            0x0005236c07b3be89, 0x0001bc3d2a67c0c4, 0x000a4aa782aae3ee, 0x0006b3f6e4fec4c4, 0x00000532da9fab8c
        });

        /// b = 4885590095775723760407499321843594317911456947580037491039278279440296187236
        public static UnpackedScalar B = new UnpackedScalar(new ulong[]
        {
            0x000d3fae55421564, 0x000c2df24f65a4bc, 0x0005b5587d69fb0b, 0x00094c091b013b3b, 0x00000acd25605473
        });

        /// a+b = 0
        /// a-b = 4702830963113076907131374482398799845891318823599740229925345317690316127506
        public static UnpackedScalar AB = new UnpackedScalar(new ulong[]
        {
            0x000a46d80f677d12, 0x0003787a54cf8188, 0x0004954f0555c7dc, 0x000d67edc9fd8989, 0x00000a65b53f5718
        });

        // c = (2^512 - 1) % l = 1627715501170711445284395025044413883736156588369414752970002579683115011840
        public static UnpackedScalar C = new UnpackedScalar(new ulong[]
        {
            0x000611e3449c0f00, 0x000a768859347a40, 0x0007f5be65d00e1b, 0x0009a3dceec73d21, 0x00000399411b7c30
        });

        [Fact]
        public void mul_max()
        {
            var res = UnpackedScalar.mul(X, X);
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(XX.Value[i], res.Value[i]);
            }
        }

        [Fact]
        public void square_max()
        {
            var res = X.square();
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(XX.Value[i], res.Value[i]);
            }
        }

        [Fact]
        public void montgomery_mul_max()
        {
            var res = UnpackedScalar.montgomery_mul(X, X);
       
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(XX_MONT.Value[i], res.Value[i]);
            }


        }

        [Fact]
        public void montgomery_square_max()
        {
            var res =  X.montgomery_square();
       
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(XX_MONT.Value[i], res.Value[i]);
            }
        }

        [Fact]
        public void mul()
        {
            var res = UnpackedScalar.mul(X, Y);
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(XY.Value[i], res.Value[i]);
            }
        }

        [Fact]
        public void montgomery_mul()
        {
            var res = UnpackedScalar.montgomery_mul(X, Y);
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(XY_MONT.Value[i], res.Value[i]);
            }
        }

        [Fact]
        public void add()
        { var res = UnpackedScalar.add(A, B);
            var zero = UnpackedScalar.zero();
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(zero.Value[i], res.Value[i]);
            }
        }

        [Fact]
        public void sub()
        {
            var res = UnpackedScalar.sub(A, B);
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(AB.Value[i], res.Value[i]);
            }
        }

        [Fact]
        public void from_bytes_wide()
        {
            var bignum = Enumerable.Repeat((byte)255, 64).ToArray(); // 2^512 - 1
            var reduced =UnpackedScalar.from_bytes_wide(bignum);
            Console.WriteLine("{0}", reduced);
            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(C.Value[i], reduced.Value[i]);
            }
        }
    }

}