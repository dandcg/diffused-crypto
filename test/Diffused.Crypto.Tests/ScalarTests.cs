using Diffused.Crypto.Curve;

namespace Diffused.Crypto.Tests
{
    public class ScalarTests
    {
        /// x = 2238329342913194256032495932344128051776374960164957527413114840482143558222
        public static Scalar X = new Scalar
        {
            bytes = new byte[]
            {
                0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84,
                0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2, 0x7d, 0x52,
                0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44,
                0xd4, 0x49, 0xf4, 0xa8, 0x79, 0xd9, 0xf2, 0x04
            }
        };

        /// 1/x = 6859937278830797291664592131120606308688036382723378951768035303146619657244
        public static Scalar XINV = new Scalar
        {
            bytes = new byte[]
            {
                0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb,
                0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01, 0x63, 0x47,
                0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96,
                0xd5, 0x0b, 0xcd, 0x7a, 0x3f, 0x96, 0x2a, 0x0f
            }
        };

        /// y = 2592331292931086675770238855846338635550719849568364935475441891787804997264
        public static Scalar Y = new Scalar
        {
            bytes = new byte[]
            {
                0x90, 0x76, 0x33, 0xfe, 0x1c, 0x4b, 0x66, 0xa4,
                0xa2, 0x8d, 0x2d, 0xd7, 0x67, 0x83, 0x86, 0xc3,
                0x53, 0xd0, 0xde, 0x54, 0x55, 0xd4, 0xfc, 0x9d,
                0xe8, 0xef, 0x7a, 0xc3, 0x1f, 0x35, 0xbb, 0x05
            }
        };

        /// x*y = 5690045403673944803228348699031245560686958845067437804563560795922180092780
        public static Scalar X_TIMES_Y = new Scalar
        {
            bytes = new byte[]
            {
                0x6c, 0x33, 0x74, 0xa1, 0x89, 0x4f, 0x62, 0x21,
                0x0a, 0xaa, 0x2f, 0xe1, 0x86, 0xa6, 0xf9, 0x2c,
                0xe0, 0xaa, 0x75, 0xc2, 0x77, 0x95, 0x81, 0xc2,
                0x95, 0xfc, 0x08, 0x17, 0x9a, 0x73, 0x94, 0x0c
            }
        };

        /// sage: l = 2^252 + 27742317777372353535851937790883648493
        /// sage: big = 2^256 - 1
        /// sage: repr((big % l).digits(256))
        public static Scalar CANONICAL_2_256_MINUS_1 = new Scalar
        {
            bytes = new byte[]
            {
                28, 149, 152, 141, 116, 49, 236, 214,
                112, 207, 125, 115, 244, 91, 239, 198,
                254, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 15
            }
        };

        public static Scalar A_SCALAR = new Scalar
        {
            bytes = new byte[]
            {
                0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d,
                0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8, 0x26, 0x4d,
                0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1,
                0x58, 0x9e, 0x7b, 0x7f, 0x23, 0x76, 0xef, 0x09
            }
        };

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

//    #[test]
//    fn fuzzer_testcase_reduction() {
//        // LE bytes of 24519928653854221733733552434404946937899825954937634815
//        let a_bytes = [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//        // LE bytes of 4975441334397345751130612518500927154628011511324180036903450236863266160640
//        let b_bytes = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 210, 210, 210, 255, 255, 255, 255, 10];
//        // LE bytes of 6432735165214683820902750800207468552549813371247423777071615116673864412038
//        let c_bytes = [134, 171, 119, 216, 180, 128, 178, 62, 171, 132, 32, 62, 34, 119, 104, 193, 47, 215, 181, 250, 14, 207, 172, 93, 75, 207, 211, 103, 144, 204, 56, 14];

//        let a = Scalar::from_bytes_mod_order(a_bytes);
//        let b = Scalar::from_bytes_mod_order(b_bytes);
//        let c = Scalar::from_bytes_mod_order(c_bytes);

//        let mut tmp = [0u8; 64];

//        // also_a = (a mod l)
//        tmp[0..32].copy_from_slice(&a_bytes[..]);
//        let also_a = Scalar::from_bytes_mod_order_wide(&tmp);

//        // also_b = (b mod l)
//        tmp[0..32].copy_from_slice(&b_bytes[..]);
//        let also_b = Scalar::from_bytes_mod_order_wide(&tmp);

//        let expected_c = &a * &b;
//        let also_expected_c = &also_a * &also_b;

//        assert_eq!(c, expected_c);
//        assert_eq!(c, also_expected_c);
//    }

//    #[test]
//    fn non_adjacent_form() {
//        let naf = A_SCALAR.non_adjacent_form(5);
//        for i in 0..256 {
//            assert_eq!(naf[i], A_NAF[i]);
//        }
//    }

//    #[test]
//    fn from_u64() {
//        let val: u64 = 0xdeadbeefdeadbeef;
//        let s = Scalar::from(val);
//        assert_eq!(s[7], 0xde);
//        assert_eq!(s[6], 0xad);
//        assert_eq!(s[5], 0xbe);
//        assert_eq!(s[4], 0xef);
//        assert_eq!(s[3], 0xde);
//        assert_eq!(s[2], 0xad);
//        assert_eq!(s[1], 0xbe);
//        assert_eq!(s[0], 0xef);
//    }

//    #[test]
//    fn scalar_mul_by_one() {
//        let test_scalar = &X * &Scalar::one();
//        for i in 0..32 {
//            assert!(test_scalar[i] == X[i]);
//        }
//    }

//    #[test]
//    fn impl_add() {
//        let two = Scalar::from(2u64);
//        let one = Scalar::one();
//        let should_be_two = &one + &one;
//        assert_eq!(should_be_two, two);
//    }

//    #[allow(non_snake_case)]
//    #[test]
//    fn impl_mul() {
//        let should_be_X_times_Y = &X * &Y;
//        assert_eq!(should_be_X_times_Y, X_TIMES_Y);
//    }

//    #[allow(non_snake_case)]
//    #[test]
//    fn impl_product() {
//        // Test that product works for non-empty iterators
//        let X_Y_vector = vec![X, Y];
//        let should_be_X_times_Y: Scalar = X_Y_vector.iter().product();
//        assert_eq!(should_be_X_times_Y, X_TIMES_Y);

//        // Test that product works for the empty iterator
//        let one = Scalar::one();
//        let empty_vector = vec![];
//        let should_be_one: Scalar = empty_vector.iter().product();
//        assert_eq!(should_be_one, one);

//        // Test that product works for iterators where Item = Scalar
//        let xs = [Scalar::from(2u64); 10];
//        let ys = [Scalar::from(3u64); 10];
//        // now zs is an iterator with Item = Scalar
//        let zs = xs.iter().zip(ys.iter()).map(|(x,y)| x * y);

//        let x_prod: Scalar = xs.iter().product();
//        let y_prod: Scalar = ys.iter().product();
//        let z_prod: Scalar = zs.product();

//        assert_eq!(x_prod, Scalar::from(1024u64));
//        assert_eq!(y_prod, Scalar::from(59049u64));
//        assert_eq!(z_prod, Scalar::from(60466176u64));
//        assert_eq!(x_prod * y_prod, z_prod);

//    }

//    #[test]
//    fn impl_sum() {

//        // Test that sum works for non-empty iterators
//        let two = Scalar::from(2u64);
//        let one_vector = vec![Scalar::one(), Scalar::one()];
//        let should_be_two: Scalar = one_vector.iter().sum();
//        assert_eq!(should_be_two, two);

//        // Test that sum works for the empty iterator
//        let zero = Scalar::zero();
//        let empty_vector = vec![];
//        let should_be_zero: Scalar = empty_vector.iter().sum();
//        assert_eq!(should_be_zero, zero);

//        // Test that sum works for owned types
//        let xs = [Scalar::from(1u64); 10];
//        let ys = [Scalar::from(2u64); 10];
//        // now zs is an iterator with Item = Scalar
//        let zs = xs.iter().zip(ys.iter()).map(|(x,y)| x + y);

//        let x_sum: Scalar = xs.iter().sum();
//        let y_sum: Scalar = ys.iter().sum();
//        let z_sum: Scalar = zs.sum();

//        assert_eq!(x_sum, Scalar::from(10u64));
//        assert_eq!(y_sum, Scalar::from(20u64));
//        assert_eq!(z_sum, Scalar::from(30u64));
//        assert_eq!(x_sum + y_sum, z_sum);
//    }

//    #[test]
//    fn square() {
//        let expected = &X * &X;
//        let actual = X.unpack().square().pack();
//        for i in 0..32 {
//            assert!(expected[i] == actual[i]);
//        }
//    }

//    #[test]
//    fn reduce() {
//        let biggest = Scalar::from_bytes_mod_order([0xff; 32]);
//        assert_eq!(biggest, CANONICAL_2_256_MINUS_1);
//    }

//    #[test]
//    fn from_bytes_mod_order_wide() {
//        let mut bignum = [0u8; 64];
//        // set bignum = x + 2^256x
//        for i in 0..32 {
//            bignum[   i] = X[i];
//            bignum[32+i] = X[i];
//        }
//        // 3958878930004874126169954872055634648693766179881526445624823978500314864344
//        // = x + 2^256x (mod l)
//        let reduced = Scalar{
//            bytes: [
//                216, 154, 179, 139, 210, 121,   2,  71,
//                 69,  99, 158, 216,  23, 173,  63, 100,
//                204,   0,  91,  50, 219, 153,  57, 249,
//                 28,  82,  31, 197, 100, 165, 192,   8,
//            ],
//        };
//        let test_red = Scalar::from_bytes_mod_order_wide(&bignum);
//        for i in 0..32 {
//            assert!(test_red[i] == reduced[i]);
//        }
//    }

//    #[allow(non_snake_case)]
//    #[test]
//    fn invert() {
//        let inv_X = X.invert();
//        assert_eq!(inv_X, XINV);
//        let should_be_one = &inv_X * &X;
//        assert_eq!(should_be_one, Scalar::one());
//    }

//    // Negating a scalar twice should result in the original scalar.
//    #[allow(non_snake_case)]
//    #[test]
//    fn neg_twice_is_identity() {
//        let negative_X = -&X;
//        let should_be_X = -&negative_X;

//        assert_eq!(should_be_X, X);
//    }

//    #[test]
//    fn to_bytes_from_bytes_roundtrips() {
//        let unpacked = X.unpack();
//        let bytes = unpacked.to_bytes();
//        let should_be_unpacked = UnpackedScalar::from_bytes(&bytes);

//        assert_eq!(should_be_unpacked.0, unpacked.0);
//    }

//    #[test]
//    fn montgomery_reduce_matches_from_bytes_mod_order_wide() {
//        let mut bignum = [0u8; 64];

//        // set bignum = x + 2^256x
//        for i in 0..32 {
//            bignum[   i] = X[i];
//            bignum[32+i] = X[i];
//        }
//        // x + 2^256x (mod l)
//        //         = 3958878930004874126169954872055634648693766179881526445624823978500314864344
//        let expected = Scalar{
//            bytes: [
//                216, 154, 179, 139, 210, 121,   2,  71,
//                 69,  99, 158, 216,  23, 173,  63, 100,
//                204,   0,  91,  50, 219, 153,  57, 249,
//                 28,  82,  31, 197, 100, 165, 192,   8
//            ],
//        };
//        let reduced = Scalar::from_bytes_mod_order_wide(&bignum);

//        // The reduced scalar should match the expected
//        assert_eq!(reduced.bytes, expected.bytes);

//        //  (x + 2^256x) * R
//        let interim = UnpackedScalar::mul_internal(&UnpackedScalar::from_bytes_wide(&bignum),
//                                                   &constants::R);
//        // ((x + 2^256x) * R) / R  (mod l)
//        let montgomery_reduced = UnpackedScalar::montgomery_reduce(&interim);

//        // The Montgomery reduced scalar should match the reduced one, as well as the expected
//        assert_eq!(montgomery_reduced.0, reduced.unpack().0);
//        assert_eq!(montgomery_reduced.0, expected.unpack().0)
//    }

//    #[test]
//    fn canonical_decoding() {
//        // canonical encoding of 1667457891
//        let canonical_bytes = [99, 99, 99, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,];

//        // encoding of
//        //   7265385991361016183439748078976496179028704920197054998554201349516117938192
//        // = 28380414028753969466561515933501938171588560817147392552250411230663687203 (mod l)
//        // non_canonical because unreduced mod l
//        let non_canonical_bytes_because_unreduced = [16; 32];

//        // encoding with high bit set, to check that the parser isn't pre-masking the high bit
//        let non_canonical_bytes_because_highbit = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128];

//        assert!( Scalar::from_canonical_bytes(canonical_bytes).is_some() );
//        assert!( Scalar::from_canonical_bytes(non_canonical_bytes_because_unreduced).is_none() );
//        assert!( Scalar::from_canonical_bytes(non_canonical_bytes_because_highbit).is_none() );
//    }

//    #[test]
//    #[cfg(feature = "serde")]
//    fn serde_bincode_scalar_roundtrip() {
//        use bincode;
//        let output = bincode::serialize(&X).unwrap();
//        let parsed: Scalar = bincode::deserialize(&output).unwrap();
//        assert_eq!(parsed, X);
//    }

//    #[cfg(debug_assertions)]
//    #[test]
//    #[should_panic]
//    fn batch_invert_with_a_zero_input_panics() {
//        let mut xs = vec![Scalar::one(); 16];
//        xs[3] = Scalar::zero();
//        // This should panic in debug mode.
//        Scalar::batch_invert(&mut xs);
//    }

//    #[test]
//    fn batch_invert_empty() {
//        assert_eq!(Scalar::one(), Scalar::batch_invert(&mut []));
//    }

//    #[test]
//    fn batch_invert_consistency() {
//        let mut x = Scalar::from(1u64);
//        let mut v1: Vec<_> = (0..16).map(|_| {let tmp = x; x = x + x; tmp}).collect();
//        let v2 = v1.clone();

//        let expected: Scalar = v1.iter().product();
//        let expected = expected.invert();
//        let ret = Scalar::batch_invert(&mut v1);
//        assert_eq!(ret, expected);

//        for (a, b) in v1.iter().zip(v2.iter()) {
//            assert_eq!(a * b, Scalar::one());
//        }
//    }
//}
    }
}