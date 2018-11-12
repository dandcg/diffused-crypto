using System;
using System.Linq;
using Diffused.Crypto.Curve;
using Xunit;

namespace Diffused.Crypto.Tests.Curve
{
    public class ScalarTests
    {
        /// x = 2238329342913194256032495932344128051776374960164957527413114840482143558222
        public static Scalar X = new Scalar
        (
            new byte[]
            {
                0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84,
                0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2, 0x7d, 0x52,
                0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44,
                0xd4, 0x49, 0xf4, 0xa8, 0x79, 0xd9, 0xf2, 0x04
            }
        );

        /// 1/x = 6859937278830797291664592131120606308688036382723378951768035303146619657244
        public static Scalar XINV = new Scalar
        (
            new byte[]
            {
                0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb,
                0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01, 0x63, 0x47,
                0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96,
                0xd5, 0x0b, 0xcd, 0x7a, 0x3f, 0x96, 0x2a, 0x0f
            }
        );

        /// y = 2592331292931086675770238855846338635550719849568364935475441891787804997264
        public static Scalar Y = new Scalar
        (
            new byte[]
            {
                0x90, 0x76, 0x33, 0xfe, 0x1c, 0x4b, 0x66, 0xa4,
                0xa2, 0x8d, 0x2d, 0xd7, 0x67, 0x83, 0x86, 0xc3,
                0x53, 0xd0, 0xde, 0x54, 0x55, 0xd4, 0xfc, 0x9d,
                0xe8, 0xef, 0x7a, 0xc3, 0x1f, 0x35, 0xbb, 0x05
            }
        );

        /// x*y = 5690045403673944803228348699031245560686958845067437804563560795922180092780
        public static Scalar X_TIMES_Y = new Scalar
        (
            new byte[]
            {
                0x6c, 0x33, 0x74, 0xa1, 0x89, 0x4f, 0x62, 0x21,
                0x0a, 0xaa, 0x2f, 0xe1, 0x86, 0xa6, 0xf9, 0x2c,
                0xe0, 0xaa, 0x75, 0xc2, 0x77, 0x95, 0x81, 0xc2,
                0x95, 0xfc, 0x08, 0x17, 0x9a, 0x73, 0x94, 0x0c
            }
        );

        /// sage: l = 2^252 + 27742317777372353535851937790883648493
        /// sage: big = 2^256 - 1
        /// sage: repr((big % l).digits(256))
        public static Scalar CANONICAL_2_256_MINUS_1 = new Scalar
        (
            new byte[]
            {
                28, 149, 152, 141, 116, 49, 236, 214,
                112, 207, 125, 115, 244, 91, 239, 198,
                254, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 15
            }
        );

        public static Scalar A_SCALAR = new Scalar
        (
            new byte[]
            {
                0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d,
                0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8, 0x26, 0x4d,
                0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1,
                0x58, 0x9e, 0x7b, 0x7f, 0x23, 0x76, 0xef, 0x09
            }
        );

        public static sbyte[] A_NAF =
        {
            0, 13, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, -11, 0, 0, 0, 0, 3, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 9, 0, 0, 0, 0, -5, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 11, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0,
            -9, 0, 0, 0, 0, 0, -3, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 9, 0,
            0, 0, 0, -15, 0, 0, 0, 0, -7, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, -3, 0,
            0, 0, 0, -11, 0, 0, 0, 0, -7, 0, 0, 0, 0, -13, 0, 0, 0, 0, 11, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 1, 0, 0,
            0, 0, 0, -15, 0, 0, 0, 0, 1, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 13, 0, 0, 0,
            0, 0, 0, 11, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, -9, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 7,
            0, 0, 0, 0, 0, -15, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 15, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0
        };

        [Fact]
        public void fuzzer_testcase_reduction()
        {
            // LE bytes of 24519928653854221733733552434404946937899825954937634815
            var aBytes = new byte[] {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            // LE bytes of 4975441334397345751130612518500927154628011511324180036903450236863266160640
            var bBytes = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 210, 210, 210, 255, 255, 255, 255, 10};
            // LE bytes of 6432735165214683820902750800207468552549813371247423777071615116673864412038
            var cBytes = new byte[] {134, 171, 119, 216, 180, 128, 178, 62, 171, 132, 32, 62, 34, 119, 104, 193, 47, 215, 181, 250, 14, 207, 172, 93, 75, 207, 211, 103, 144, 204, 56, 14};

            var a = Scalar.from_bytes_mod_order(aBytes);
            var b = Scalar.from_bytes_mod_order(bBytes);
            var c = Scalar.from_bytes_mod_order(cBytes);

            var tmp = new byte[64];

            // also_a = (a mod l)
            aBytes.CopyTo(tmp, 0);
            var alsoA = Scalar.from_bytes_mod_order_wide(tmp);

            // also_b = (b mod l)
            bBytes.CopyTo(tmp, 0);
            var alsoB = Scalar.from_bytes_mod_order_wide(tmp);

            var expectedC = a * b;
            var alsoExpectedC = alsoA * alsoB;

            Assert.Equal(expectedC, c);
            Assert.Equal(alsoExpectedC, c);
        }

        [Fact]
        public void non_adjacent_form()
        {
            var naf = A_SCALAR.non_adjacent_form(5);

            for (int i = 0; i < 256; i++)
            {
                Console.WriteLine($"{i}) {A_NAF[i]}, {naf[i]}");
                Assert.Equal(A_NAF[i], naf[i]);
            }
        }

        [Fact]
        public void from_u64()
        {
            ulong val = 0xdeadbeefdeadbeef;
            var s = Scalar.from(val).Value;
            Assert.Equal(s[7], 0xde);
            Assert.Equal(s[6], 0xad);
            Assert.Equal(s[5], 0xbe);
            Assert.Equal(s[4], 0xef);
            Assert.Equal(s[3], 0xde);
            Assert.Equal(s[2], 0xad);
            Assert.Equal(s[1], 0xbe);
            Assert.Equal(s[0], 0xef);
        }

        [Fact]
        public void scalar_mul_by_one()
        {
            var test_scalar = X * Scalar.one();
            for (int i = 0; i < 32; i++)
            {
                Assert.Equal(test_scalar.Value[i], X.Value[i]);
            }
        }

        [Fact]
        public void impl_add()
        {
            var two = Scalar.from(2);
            var one = Scalar.one();
            var should_be_two = one + one;

            Assert.Equal(should_be_two.Value.ToArray(), two.Value.ToArray());
        }

        [Fact]
        public void impl_mul()
        {
            var should_be_X_times_Y = X * Y;
            Assert.Equal(should_be_X_times_Y, X_TIMES_Y);
        }

        [Fact]
        public void impl_product()
        {
            // Test that product works for non-empty iterators
            //var X_Y_vector = vec![X, Y];
            //var should_be_X_times_Y: Scalar = X_Y_vector.iter().product();
            //assert_eq!(should_be_X_times_Y, X_TIMES_Y);

            // Test that product works for the empty iterator
            //var one = Scalar.one();
            //var empty_vector = vec![];
            //var should_be_one: Scalar = empty_vector.iter().product();
            //assert_eq!(should_be_one, one);

            //// Test that product works for iterators where Item = Scalar
            //var xs =Enumerable.Repeat(Scalar.from((ulong)2), 10).ToArray();;
            //var ys = Enumerable.Repeat(Scalar.from((ulong)3), 10).ToArray();;
            //// now zs is an iterator with Item = Scalar
            //var zs = xs.iter().zip(ys.iter()).map(| (x, y) | x * y);

            //Scalar x_prod = xs.iter().product();
            //Scalar  y_prod = Scalar = ys.iter().product();
            //Scalar  z_prod =  Scalar = zs.product();

            //Assert.Equal(x_prod, Scalar.from(1024u64));
            //Assert.Equal(y_prod, Scalar.from(59049u64));
            //Assert.Equal(z_prod, Scalar.from(60466176u64));
            //Assert.Equal(x_prod * y_prod, z_prod);
        }

        [Fact]
        public void impl_sum()
        {
            //// Test that sum works for non-empty iterators
            //let two = Scalar::from(2u64);
            //let one_vector = vec![Scalar::one(), Scalar::one()];
            //let should_be_two: Scalar = one_vector.iter().sum();
            //assert_eq!(should_be_two, two);

            //// Test that sum works for the empty iterator
            //let zero = Scalar::zero();
            //let empty_vector = vec![];
            //let should_be_zero: Scalar = empty_vector.iter().sum();
            //assert_eq!(should_be_zero, zero);

            //// Test that sum works for owned types
            //let xs = [Scalar::from(1u64); 10];
            //let ys = [Scalar::from(2u64); 10];
            //// now zs is an iterator with Item = Scalar
            //let zs = xs.iter().zip(ys.iter()).map(| (x, y) | x + y);

            //let x_sum: Scalar = xs.iter().sum();
            //let y_sum: Scalar = ys.iter().sum();
            //let z_sum: Scalar = zs.sum();

            //assert_eq!(x_sum, Scalar::from(10u64));
            //assert_eq!(y_sum, Scalar::from(20u64));
            //assert_eq!(z_sum, Scalar::from(30u64));
            //assert_eq!(x_sum + y_sum, z_sum);
        }

        [Fact]
        public void square()
        {
            var expected = X * X;
            var actual = X.unpack().square().pack();
            for (int i = 0; i < 32; i++)
            {
                Assert.Equal(expected.Value[i], actual.Value[i]);
            }
        }

        [Fact]
        public void reduce()
        {
            var bytes = Enumerable.Repeat((byte) 0xff, 32).ToArray();
            var biggest = Scalar.from_bytes_mod_order(bytes);
            Assert.Equal(biggest, CANONICAL_2_256_MINUS_1);
        }

        [Fact]
        public void from_bytes_mod_order_wide()
        {
            var bignum = new byte[64];
            // set bignum = x + 2^256x
            for (int i = 0; i < 32; i++)
            {
                bignum[i] = X.Value[i];
                bignum[32 + i] = X.Value[i];
            }

            // 3958878930004874126169954872055634648693766179881526445624823978500314864344
            // = x + 2^256x (mod l)
            var reduced = new Scalar(
                new byte[]
                {
                    216, 154, 179, 139, 210, 121, 2, 71,
                    69, 99, 158, 216, 23, 173, 63, 100,
                    204, 0, 91, 50, 219, 153, 57, 249,
                    28, 82, 31, 197, 100, 165, 192, 8
                });

            var test_red = Scalar.from_bytes_mod_order_wide(bignum);
            for (int i = 0; i < 32; i++)
            {
                Assert.Equal(test_red.Value[i], reduced.Value[i]);
            }
        }

        [Fact]
        public void invert()
        {
            var inv_X = X.invert();
            Assert.Equal(inv_X, XINV);
            var should_be_one = inv_X * X;
            Assert.Equal(should_be_one, Scalar.one());
        }

        // Negating a scalar twice should result in the original scalar.
        [Fact]
        public void neg_twice_is_identity()
        {
            var negative_X = -X;
            var should_be_X = -negative_X;

            Assert.Equal(should_be_X, X);
        }

        [Fact]
        public void to_bytes_from_bytes_roundtrips()
        {
            var unpacked = X.unpack();
            var bytes = unpacked.to_bytes();
            var should_be_unpacked = UnpackedScalar.from_bytes(bytes);

            Assert.Equal(should_be_unpacked.to_bytes(), unpacked.to_bytes());
        }

        [Fact]
        public void montgomery_reduce_matches_from_bytes_mod_order_wide()
        {
            var bignum = new byte [64];

            // set bignum = x + 2^256x
            for (int i = 0; i < 32; i++)
            {
                bignum[i] = X.Value[i];
                bignum[32 + i] = X.Value[i];
            }

            // x + 2^256x (mod l)
            //         = 3958878930004874126169954872055634648693766179881526445624823978500314864344
            var expected = new Scalar(new byte[]
            {
                216, 154, 179, 139, 210, 121, 2, 71,
                69, 99, 158, 216, 23, 173, 63, 100,
                204, 0, 91, 50, 219, 153, 57, 249,
                28, 82, 31, 197, 100, 165, 192, 8
            });

            var reduced = Scalar.from_bytes_mod_order_wide(bignum);

            // The reduced scalar should match the expected
            Assert.Equal(reduced.Value.ToArray(), expected.Value.ToArray());

            //  (x + 2^256x) * R
            var interim = UnpackedScalar.mul_internal(UnpackedScalar.from_bytes_wide(bignum).Value, Constant.R.Value);
            // ((x + 2^256x) * R) / R  (mod l)
            var montgomery_reduced = UnpackedScalar.montgomery_reduce(interim);

            // The Montgomery reduced scalar should match the reduced one, as well as the expected
            Assert.Equal(montgomery_reduced.to_bytes(), reduced.unpack().to_bytes());
            Assert.Equal(montgomery_reduced.to_bytes(), expected.unpack().to_bytes());
        }

        [Fact]
        public void canonical_decoding()
        {
            // canonical encoding of 1667457891
            var canonical_bytes = new byte[] {99, 99, 99, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

            // encoding of
            //   7265385991361016183439748078976496179028704920197054998554201349516117938192
            // = 28380414028753969466561515933501938171588560817147392552250411230663687203 (mod l)
            // non_canonical because unreduced mod l
            var non_canonical_bytes_because_unreduced = Enumerable.Repeat((byte) 16, 32).ToArray();

            // encoding with high bit set, to check that the parser isn't pre-masking the high bit
            var non_canonical_bytes_because_highbit = new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128};

            Assert.NotNull(Scalar.from_canonical_bytes(canonical_bytes));
            Assert.Null(Scalar.from_canonical_bytes(non_canonical_bytes_because_unreduced));
            Assert.Null(Scalar.from_canonical_bytes(non_canonical_bytes_because_highbit));
        }

        //[Fact]
        //public void  serde_bincode_scalar_roundtrip()
        //{
        //    use bincode;
        //    let output = bincode::serialize(&X).unwrap();
        //    let parsed: Scalar = bincode::deserialize(&output).unwrap();
        //    Assert.Equal(parsed, X);
        //}

        [Fact]
        public void batch_invert_with_a_zero_input_panics()
        {
            var xs = Enumerable.Repeat(Scalar.one(), 16).ToArray();
            xs[3] = Scalar.zero();
            // This should panic in debug mode.
            Assert.ThrowsAny<Exception>(()=>Scalar.batch_invert(xs));
        }

        [Fact]
        public void batch_invert_empty()
        {
            Assert.Equal(Scalar.one(), Scalar.batch_invert(new Scalar[] { }));
        }

        //[Fact]
        //public void  batch_invert_consistency()
        //{
        //    var x = Scalar.from((ulong)1);
        //    var v1: Vec < _ > = (0..16).map(| _ | { let tmp = x; x = x + x; tmp}).collect();
        //    var v2 = v1.clone();

        //    var expected: Scalar = v1.iter().product();
        //    var expected = expected.invert();
        //    var ret = Scalar::batch_invert(&mut v1);
        //    Assert.Equal(ret, expected);

        //    for (a, b) in v1.iter().zip(v2.iter()) {
        //        Assert.Equal(a * b, Scalar::one());
        //    }
        //}
    }
}