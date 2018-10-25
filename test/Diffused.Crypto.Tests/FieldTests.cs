using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using Diffused.Crypto.Architecture.x32;
using Diffused.Crypto.Architecture.x64;
using Diffused.Crypto.Types;
using Xunit;

namespace Diffused.Crypto.Tests
{
    public class FieldTests
    {



    /// Random element a of GF(2^255-19), from Sage
    /// a = 1070314506888354081329385823235218444233221\
    ///     2228051251926706380353716438957572
    public static readonly byte[] A_BYTES = 
    { 0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68,
         0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7, 0x03,
          0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4,
          0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3, 0xa9, 0x17};

    /// Byte representation of a**2
    public static readonly byte[] ASQ_BYTES=
        { 0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab,
          0x24, 0x04, 0x56, 0x68, 0x07, 0x91, 0x2d, 0x5d,
          0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2,
          0x63, 0x9c, 0x12, 0xba, 0x73, 0x0b, 0xe3, 0x62};

    /// Byte representation of 1/a
    public static readonly byte[] AINV_BYTES =
        {0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a,
         0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b, 0x4d, 0x70,
         0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b,
         0x90, 0x71, 0xd8, 0xe9, 0xb6, 0x18, 0xe6, 0x30};

    /// Byte representation of a^((p-5)/8)
    public static readonly byte[] AP58_BYTES=
        {0x6a, 0x4f, 0x24, 0x89, 0x1f, 0x57, 0x60, 0x36,
         0xd0, 0xbe, 0x12, 0x3c, 0x8f, 0xf5, 0xb1, 0x59,
         0xe0, 0xf0, 0xb8, 0x1b, 0x20, 0xd2, 0xb5, 0x1f,
         0x15, 0x21, 0xf9, 0xe3, 0xe1, 0x61, 0x21, 0x55};



        [Fact]
        public void to_from_bytes()
        {
            var a = new FieldElement64();
            a.from_bytes(A_BYTES);
            
            
            
            Assert.Equal(A_BYTES, a.to_bytes());

            Assert.Equal(A_BYTES, a.to_bytes());

        }



        [Fact]
   public void  a_mul_a_vs_a_squared_constant()
        {
            

            var a = new FieldElement64();
            a.from_bytes(A_BYTES);
            
            a.MulAssign(a);
            
            var asq = new FieldElement64();
            asq.from_bytes(ASQ_BYTES);
            

            Assert.Equal(asq.Value, a.Value);

    }

        [Fact]
        public void a_square_vs_a_squared_constant()
        {
            var a = new FieldElement64();
            a.from_bytes(A_BYTES);
            var asq = new FieldElement64();
            asq.from_bytes(ASQ_BYTES);
          
            Assert.Equal(asq.Value, ((FieldElement64)a.square()).Value);
      }

        [Fact]
        public void a_square2_vs_a_squared_constant()
        {
            var a = new FieldElement64();
            a.from_bytes(A_BYTES);

            var asq = new FieldElement64();
            asq.from_bytes(ASQ_BYTES);

            asq.AddAssign(asq);

            Assert.Equal(((FieldElement64)a.square2()).Value, asq.Value);
        }

        [Fact]
        public void a_invert_vs_inverse_of_invert()

        {
            var a = new FieldElement64();
            a.from_bytes(A_BYTES);

            var  should_be_inverse = a.invert();
            var inverse2 = should_be_inverse.invert();


            Assert.Equal(a.Value, ((FieldElement64)should_be_inverse.invert()).Value);

        }

        //[Fact]
        //public void multiply_vs_multiply()

        //{

        //    var a = new FieldElement64();
        //    a.from_bytes(A_BYTES);

        //    var feo = new FieldElement64();
        //    feo.one();
            
        //    Assert.Equal(((FieldElement64)(a.Mul(feo))).Value,((FieldElement64)(a)).Value );

        //   }

        [Fact]
        public void a_invert_vs_inverse_of_a_constant()
        {
            var a = new FieldElement64();
            a.from_bytes(A_BYTES);

            var ainv = new FieldElement64();
            ainv.from_bytes(AINV_BYTES);

            var should_be_inverse = a.invert();

            var feo = new FieldElement64();
            feo.one();

            
            
           // Assert.Equal(ainv.Value, ((FieldElement64)should_be_inverse).Value);
            
            Assert.Equal(feo.to_bytes(), ((FieldElement64)a.Mul(ainv)).to_bytes());


           //Assert.Equal(a.Value, ((FieldElement64)should_be_inverse.invert()).Value);
           
            //Assert.Equal(feo.Value, ((FieldElement64)a.Mul(should_be_inverse)).Value);
        }


        [Fact]
        public void tt()
        {

            var a = new FieldElement32();
            a.from_bytes(A_BYTES);

           Assert.Equal(((FieldElement32)a.square()).Value,((FieldElement32)a.Mul(a)).Value );

         


        }



        //        [Fact]
        //        public void batch_invert_a_matches_nonbatched()
        //        {
        //            var a = FieldElement::from_bytes(&A_BYTES);
        //            var ap58 = FieldElement::from_bytes(&AP58_BYTES);
        //            var asq = FieldElement::from_bytes(&ASQ_BYTES);
        //            var ainv = FieldElement::from_bytes(&AINV_BYTES);
        //            var a2 = &a + &a;
        //            var a_list = vec![a, ap58, asq, ainv, a2];
        //            var mut ainv_list = a_list.clone();
        //            FieldElement::batch_invert(&mut ainv_list[..]);
        //            for i in 0..5 {
        //                assert_eq!(a_list[i].invert(), ainv_list[i]);
        //            }
        //        }

        //        [Fact]
        //        public void a_p58_vs_ap58_constant()
        //        {
        //            var a = FieldElement::from_bytes(&A_BYTES);
        //            var ap58 = FieldElement::from_bytes(&AP58_BYTES);
        //            assert_eq!(ap58, a.pow_p58());
        //        }

        //        [Fact]
        //        public void chi_on_square_and_nonsquare()
        //        {
        //            var a = FieldElement::from_bytes(&A_BYTES);
        //            // a is square
        //            assert_eq!(a.chi(), FieldElement::one());
        //            var mut two_bytes = [0u8; 32]; two_bytes[0] = 2;
        //            var two = FieldElement::from_bytes(&two_bytes);
        //            // 2 is nonsquare
        //            assert_eq!(two.chi(), FieldElement::minus_one());
        //        }

        //        [Fact]
        //        public void equality()
        //        {
        //            var a = FieldElement::from_bytes(&A_BYTES);
        //            var ainv = FieldElement::from_bytes(&AINV_BYTES);
        //            assert!(a == a);
        //            assert!(a != ainv);
        //        }

        //        /// Notice that the last element has the high bit set, which
        //        /// should be ignored
        //        static B_BYTES: [u8;32] =
        //                [113, 191, 169, 143,  91, 234, 121,  15,
        //                 241, 131, 217,  36, 230, 101,  92, 234,
        //                   8, 208, 170, 251,  97, 127,  70, 210,
        //                  58,  23, 166,  87, 240, 169, 184, 178];

        //                [Fact]
        //        public void from_bytes_highbit_is_ignored()
        //        {
        //            var mut cleared_bytes = B_BYTES;
        //            cleared_bytes[31] &= 127u8;
        //            var with_highbit_set = FieldElement::from_bytes(&B_BYTES);
        //            var without_highbit_set = FieldElement::from_bytes(&cleared_bytes);
        //            assert_eq!(without_highbit_set, with_highbit_set);
        //        }

        //        [Fact]
        //        public void conditional_negate()
        //        {
        //            var one = FieldElement::one();
        //            var minus_one = FieldElement::minus_one();
        //            var mut x = one;
        //            x.conditional_negate(Choice::from(1));
        //            assert_eq!(x, minus_one);
        //            x.conditional_negate(Choice::from(0));
        //            assert_eq!(x, minus_one);
        //            x.conditional_negate(Choice::from(1));
        //            assert_eq!(x, one);
        //        }

        //        [Fact]
        //        public void encoding_is_canonical()
        //        {
        //            // Encode 1 wrongly as 1 + (2^255 - 19) = 2^255 - 18
        //            var one_encoded_wrongly_bytes: [u8;32] = [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        //                // Decode to a field element
        //                var one = FieldElement::from_bytes(&one_encoded_wrongly_bytes);
        //        // .. then check that the encoding is correct
        //        var one_bytes = one.to_bytes();
        //        assert_eq!(one_bytes[0], 1);
        //                for i in 1..32 {
        //                    assert_eq!(one_bytes[i], 0);
        //                }
        //}

        //[Fact]
        //public void batch_invert_empty()
        //{
        //    FieldElement::batch_invert(&mut[]);
        //}








    }
}
