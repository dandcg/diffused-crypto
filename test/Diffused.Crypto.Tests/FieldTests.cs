using System.Linq;
using Diffused.Crypto.Architecture;
using Xunit;

namespace Diffused.Crypto.Tests
{
    public class FieldTests
    {
        /// Random element a of GF(2^255-19), from Sage
        /// a = 1070314506888354081329385823235218444233221\
        /// 2228051251926706380353716438957572
        // ReSharper disable once InconsistentNaming
        public static readonly byte[] A_BYTES =
        {
            0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68,
            0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7, 0x03,
            0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4,
            0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3, 0xa9, 0x17
        };

        /// Byte representation of a**2
        // ReSharper disable once InconsistentNaming
        public static readonly byte[] ASQ_BYTES =
        {
            0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab,
            0x24, 0x04, 0x56, 0x68, 0x07, 0x91, 0x2d, 0x5d,
            0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2,
            0x63, 0x9c, 0x12, 0xba, 0x73, 0x0b, 0xe3, 0x62
        };

        /// Byte representation of 1/a
        // ReSharper disable once InconsistentNaming
        public static readonly byte[] AINV_BYTES =
        {
            0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a,
            0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b, 0x4d, 0x70,
            0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b,
            0x90, 0x71, 0xd8, 0xe9, 0xb6, 0x18, 0xe6, 0x30
        };

        /// Byte representation of a^((p-5)/8)
        // ReSharper disable once InconsistentNaming
        public static readonly byte[] AP58_BYTES =
        {
            0x6a, 0x4f, 0x24, 0x89, 0x1f, 0x57, 0x60, 0x36,
            0xd0, 0xbe, 0x12, 0x3c, 0x8f, 0xf5, 0xb1, 0x59,
            0xe0, 0xf0, 0xb8, 0x1b, 0x20, 0xd2, 0xb5, 0x1f,
            0x15, 0x21, 0xf9, 0xe3, 0xe1, 0x61, 0x21, 0x55
        };

        [Fact]
        public void to_from_bytes()
        {
            var a = FieldElement.from_bytes(A_BYTES);

            Assert.Equal(A_BYTES, a.to_bytes());

            Assert.Equal(A_BYTES, a.to_bytes());
        }

        [Fact]
        public void a_mul_a_vs_a_squared_constant()
        {
            var a = FieldElement.from_bytes(A_BYTES);

            a = a * a;

            var asq = FieldElement.from_bytes(ASQ_BYTES);

            Assert.Equal(asq, a);
        }

        [Fact]
        public void a_square_vs_a_squared_constant()
        {
            var a = FieldElement.from_bytes(A_BYTES);
            var asq = FieldElement.from_bytes(ASQ_BYTES);

            Assert.Equal(asq, a.square());
        }

        [Fact]
        public void a_square2_vs_a_squared_constant()
        {
            var a = FieldElement.from_bytes(A_BYTES);

            var asq = FieldElement.from_bytes(ASQ_BYTES);

            asq = asq + asq;

            Assert.Equal(a.square2(), asq);
        }

        [Fact]
        public void a_invert_vs_inverse_of_invert()
        {
            var a = FieldElement.from_bytes(A_BYTES);

            var shouldBeInverse = a.invert();
   
            Assert.Equal(a, shouldBeInverse.invert());
        }

        [Fact]
        public void a_invert_vs_inverse_of_a_constant()
        {
            var a = FieldElement.from_bytes(A_BYTES);

            var ainv = FieldElement.from_bytes(AINV_BYTES);

            var shouldBeInverse = a.invert();

            var feo = FieldElement.one();

            Assert.Equal(ainv, shouldBeInverse);

            Assert.Equal(feo, a * shouldBeInverse);
        }

        [Fact]
        public void batch_invert_a_matches_nonbatched()
        {
            var a = FieldElement.from_bytes(A_BYTES);
            var ap58 = FieldElement.from_bytes(AP58_BYTES);
            var asq = FieldElement.from_bytes(ASQ_BYTES);
            var ainv = FieldElement.from_bytes(AINV_BYTES);
            var a2 = a + a;

            var aList = new[] {a, ap58, asq, ainv, a2};

            var ainvList = aList.ToArray();

            FieldElement.batch_invert(ainvList);

            for (int i = 0; i < 5; i++)
            {
                Assert.Equal(aList[i].invert(), ainvList[i]);
            }
        }

        [Fact]
        public void a_p58_vs_ap58_constant()
        {
            var a = FieldElement.from_bytes(A_BYTES);
            var ap58 = FieldElement.from_bytes(AP58_BYTES);
            Assert.Equal(ap58, a.pow_p58());
        }

        [Fact]
        public void chi_on_square_and_nonsquare()
        {
            var a = FieldElement.from_bytes(A_BYTES);
            // a is square
            Assert.Equal(a.chi(), FieldElement.one());
            var twoBytes = new byte[32];
            twoBytes[0] = 2;
            var two = FieldElement.from_bytes(twoBytes);
            // 2 is non-square
            Assert.Equal(two.chi(), FieldElement.minus_one());
        }

        [Fact]
        public void equality_check()
        {
            var a = FieldElement.from_bytes(A_BYTES);
            var ainv = FieldElement.from_bytes(AINV_BYTES);

            // ReSharper disable once EqualExpressionComparison
            #pragma warning disable CS1718 // Comparison made to same variable
            Assert.True(a == a);
            #pragma warning restore CS1718 // Comparison made to same variable
            Assert.True(a != ainv);
        }

        /// Notice that the last element has the high bit set, which
        /// should be ignored
        // ReSharper disable once InconsistentNaming
        private static readonly byte[] B_BYTES = {
            113, 191, 169, 143, 91, 234, 121, 15,
            241, 131, 217, 36, 230, 101, 92, 234,
            8, 208, 170, 251, 97, 127, 70, 210,
            58, 23, 166, 87, 240, 169, 184, 178
        };

        [Fact]

        public void from_bytes_highbit_is_ignored()
        {
            var clearedBytes = B_BYTES;
            clearedBytes[31] &= 127;
            var withHighbitSet = FieldElement.from_bytes(B_BYTES);
            var withoutHighbitSet = FieldElement.from_bytes(clearedBytes);
            Assert.Equal(withoutHighbitSet, withHighbitSet);
        }

        [Fact]
        public void conditional_negate()
        {
            var one = FieldElement.one();
            var minusOne = FieldElement.minus_one();
            var x = one;
            x.conditional_negate(true);
            Assert.Equal(x, minusOne);
            x.conditional_negate(false);
            Assert.Equal(x, minusOne);
            x.conditional_negate(true);
            Assert.Equal(x, one);
        }

        [Fact]
        public void encoding_is_canonical()
        {
            // Encode 1 wrongly as 1 + (2^255 - 19) = 2^255 - 18
            var oneEncodedWronglyBytes = new byte[] {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};
            // Decode to a field element
            var one = FieldElement.from_bytes(oneEncodedWronglyBytes);
            // .. then check that the encoding is correct
            var oneBytes = one.to_bytes();
            Assert.Equal(1, oneBytes[0]);

            for (int i = 1; i < 32; i++)
            {
                Assert.Equal(0, oneBytes[i]);
            }
        }

        [Fact]
        public void batch_invert_empty()
        {
            FieldElement.batch_invert(new FieldElement[] { });
        }
    }
}