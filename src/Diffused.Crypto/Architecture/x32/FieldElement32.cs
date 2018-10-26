//using System;
//using System.Diagnostics;

//namespace Diffused.Crypto.Architecture.x32
//{
//    public class FieldElement32 : FieldElement
//    {
//        public uint[] Value { get; protected set; }

//        public FieldElement32()
//        {
//        }

//        public FieldElement32(uint[] value)
//        {
//            Value = value;
//        }

//        public override void negate()
//        {
//            throw new NotImplementedException();
//        }

//        public override void zero()
//        {
//            Value = new uint[10] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
//        }

//        public override void one()
//        {
//            Value = new uint[10] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
//        }

//        public override void minus_one()
//        {
//            Value = new uint[10]
//            {
//                0x3ffffec, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff,
//                0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff
//            };
//        }

//        /// Given unreduced coefficients `z[0], ..., z[9]` of any size,
//        /// carry and reduce them mod p to obtain a `FieldElement32`
//        /// whose coefficients have excess `b
//        /// < 0.007`.
//        /// 
//        ///     In other words, each coefficient of the result is bounded by
//        ///     either `2^(25 + 0.007)` or `2^(26 + 0.007)`, as appropriate.
//        private uint[] reduce(Span<ulong> z)
//        {
//            const ulong LOW_25_BITS = (1 << 25) - 1;
//            const ulong LOW_26_BITS = (1 << 26) - 1;

//            /// Carry the value from limb i = 0..8 to limb i+1

//            void carry(Span<ulong> zi, int i)
//            {
//                Debug.Assert(i < 9);
//                if (i % 2 == 0)
//                {
//                    // Even limbs have 26 bits
//                    zi[i + 1] += zi[i] >> 26;
//                    zi[i] &= LOW_26_BITS;
//                }
//                else
//                {
//                    // Odd limbs have 25 bits
//                    zi[i + 1] += zi[i] >> 25;
//                    zi[i] &= LOW_25_BITS;
//                }
//            }

//            // Perform two halves of the carry chain in parallel.
//            carry(z, 0);
//            carry(z, 4);
//            carry(z, 1);
//            carry(z, 5);
//            carry(z, 2);
//            carry(z, 6);
//            carry(z, 3);
//            carry(z, 7);
//            // Since z[3] < 2^64, c < 2^(64-25) = 2^39,
//            // so    z[4] < 2^26 + 2^39 < 2^39.0002
//            carry(z, 4);
//            carry(z, 8);
//            // Now z[4] < 2^26
//            // and z[5] < 2^25 + 2^13.0002 < 2^25.0004 (good enough)

//            // Last carry has a multiplication by 19:
//            z[0] += 19 * (z[9] >> 25);
//            z[9] &= LOW_25_BITS;

//            // Since z[9] < 2^64, c < 2^(64-25) = 2^39,
//            //    so z[0] + 19*c < 2^26 + 2^43.248 < 2^43.249.
//            carry(z, 0);
//            // Now z[1] < 2^25 - 2^(43.249 - 26)
//            //          < 2^25.007 (good enough)
//            // and we're done.

//            return new[] {(uint) z[0], (uint) z[1], (uint) z[2], (uint) z[3], (uint) z[4], (uint) z[5], (uint) z[6], (uint) z[7], (uint) z[8], (uint) z[9]};
//        }

//        public override void from_bytes(byte[] data)
//        {
//            ulong load3(ReadOnlySpan<byte> b)

//            {
//                return b[0] | ((ulong) b[1] << 8) | ((ulong) b[2] << 16);
//            }

//            ulong load4(ReadOnlySpan<byte> b)

//            {
//                return b[0] | ((ulong) b[1] << 8) | ((ulong) b[2] << 16) | ((ulong) b[3] << 24);
//            }

//            ulong[] h = new ulong[10];
//            const ulong LOW_23_BITS = (1 << 23) - 1;

//            Span<byte> dataSpan = data;

//            h[0] = load4(dataSpan.Slice(0));
//            h[1] = load3(dataSpan.Slice(4)) << 6;
//            h[2] = load3(dataSpan.Slice(7)) << 5;
//            h[3] = load3(dataSpan.Slice(10)) << 3;
//            h[4] = load3(dataSpan.Slice(13)) << 2;
//            h[5] = load4(dataSpan.Slice(6));
//            h[6] = load3(dataSpan.Slice(20)) << 7;
//            h[7] = load3(dataSpan.Slice(23)) << 5;
//            h[8] = load3(dataSpan.Slice(26)) << 4;
//            h[9] = (load3(dataSpan.Slice(29)) & LOW_23_BITS) << 2;

//            reduce(h);

//            Value = new uint[10];

//            for (int i = 0; i < 10; i++)
//            {
//                Value[i] = (uint) h[i];
//            }
//        }

//        public override byte[] to_bytes()
//        {
//            throw new NotImplementedException();
//        }

//        public override FieldElement pow2k(uint k)
//        {
//            Debug.Assert(k > 0);

//            var z = square();
//            for (int i = 0; i < k; i++)
//            {
//                z = z.square();
//            }

//            return z;
//        }

//        public override FieldElement Mul(FieldElement rhs)
//        {
//            return new FieldElement32(MulInternal(Value, ((FieldElement32) rhs).Value));
//        }

//        private uint[] MulInternal(uint[] x, uint[] y)
//        {
//            /// Helper function to multiply two 32-bit integers with 64 bits
//            /// of output.

//            ulong m(uint ix, uint iy)
//            {
//                return ix * (ulong) iy;
//            }

//            // Alias self, _rhs for more readable formulas
//            //--let x: &[u32;10] = &self.0; let y: &[u32;10] = &_rhs.0;

//            // We assume that the input limbs x[i], y[i] are bounded by:
//            //
//            // x[i], y[i] < 2^(26 + b) if i even
//            // x[i], y[i] < 2^(25 + b) if i odd
//            //
//            // where b is a (real) parameter representing the excess bits of
//            // the limbs.  We track the bitsizes of all variables through
//            // the computation and solve at the end for the allowable
//            // headroom bitsize b (which determines how many additions we
//            // can perform between reductions or multiplications).

//            var y1_19 = 19 * y[1]; // This fits in a u32
//            var y2_19 = 19 * y[2]; // iff 26 + b + lg(19) < 32
//            var y3_19 = 19 * y[3]; // if  b < 32 - 26 - 4.248 = 1.752
//            var y4_19 = 19 * y[4];
//            var y5_19 = 19 * y[5]; // below, b<2.5: this is a bottleneck,
//            var y6_19 = 19 * y[6]; // could be avoided by promoting to
//            var y7_19 = 19 * y[7]; // u64 here instead of in m()
//            var y8_19 = 19 * y[8];
//            var y9_19 = 19 * y[9];

//            // What happens when we multiply x[i] with y[j] and place the
//            // result into the (i+j)-th limb?
//            //
//            // x[i]      represents the value x[i]*2^ceil(i*51/2)
//            // y[j]      represents the value y[j]*2^ceil(j*51/2)
//            // z[i+j]    represents the value z[i+j]*2^ceil((i+j)*51/2)
//            // x[i]*y[j] represents the value x[i]*y[i]*2^(ceil(i*51/2)+ceil(j*51/2))
//            //
//            // Since the radix is already accounted for, the result placed
//            // into the (i+j)-th limb should be
//            //
//            // x[i]*y[i]*2^(ceil(i*51/2)+ceil(j*51/2) - ceil((i+j)*51/2)).
//            //
//            // The value of ceil(i*51/2)+ceil(j*51/2) - ceil((i+j)*51/2) is
//            // 1 when both i and j are odd, and 0 otherwise.  So we add
//            //
//            //   x[i]*y[j] if either i or j is even
//            // 2*x[i]*y[j] if i and j are both odd
//            //
//            // by using precomputed multiples of x[i] for odd i:

//            var x1_2 = 2 * x[1]; // This fits in a u32 iff 25 + b + 1 < 32
//            var x3_2 = 2 * x[3]; //                    iff b < 6
//            var x5_2 = 2 * x[5];
//            var x7_2 = 2 * x[7];
//            var x9_2 = 2 * x[9];

//            var z0 = m(x[0], y[0]) + m(x1_2, y9_19) + m(x[2], y8_19) + m(x3_2, y7_19) + m(x[4], y6_19) + m(x5_2, y5_19) + m(x[6], y4_19) + m(x7_2, y3_19) + m(x[8], y2_19) + m(x9_2, y1_19);
//            var z1 = m(x[0], y[1]) + m(x[1], y[0]) + m(x[2], y9_19) + m(x[3], y8_19) + m(x[4], y7_19) + m(x[5], y6_19) + m(x[6], y5_19) + m(x[7], y4_19) + m(x[8], y3_19) + m(x[9], y2_19);
//            var z2 = m(x[0], y[2]) + m(x1_2, y[1]) + m(x[2], y[0]) + m(x3_2, y9_19) + m(x[4], y8_19) + m(x5_2, y7_19) + m(x[6], y6_19) + m(x7_2, y5_19) + m(x[8], y4_19) + m(x9_2, y3_19);
//            var z3 = m(x[0], y[3]) + m(x[1], y[2]) + m(x[2], y[1]) + m(x[3], y[0]) + m(x[4], y9_19) + m(x[5], y8_19) + m(x[6], y7_19) + m(x[7], y6_19) + m(x[8], y5_19) + m(x[9], y4_19);
//            var z4 = m(x[0], y[4]) + m(x1_2, y[3]) + m(x[2], y[2]) + m(x3_2, y[1]) + m(x[4], y[0]) + m(x5_2, y9_19) + m(x[6], y8_19) + m(x7_2, y7_19) + m(x[8], y6_19) + m(x9_2, y5_19);
//            var z5 = m(x[0], y[5]) + m(x[1], y[4]) + m(x[2], y[3]) + m(x[3], y[2]) + m(x[4], y[1]) + m(x[5], y[0]) + m(x[6], y9_19) + m(x[7], y8_19) + m(x[8], y7_19) + m(x[9], y6_19);
//            var z6 = m(x[0], y[6]) + m(x1_2, y[5]) + m(x[2], y[4]) + m(x3_2, y[3]) + m(x[4], y[2]) + m(x5_2, y[1]) + m(x[6], y[0]) + m(x7_2, y9_19) + m(x[8], y8_19) + m(x9_2, y7_19);
//            var z7 = m(x[0], y[7]) + m(x[1], y[6]) + m(x[2], y[5]) + m(x[3], y[4]) + m(x[4], y[3]) + m(x[5], y[2]) + m(x[6], y[1]) + m(x[7], y[0]) + m(x[8], y9_19) + m(x[9], y8_19);
//            var z8 = m(x[0], y[8]) + m(x1_2, y[7]) + m(x[2], y[6]) + m(x3_2, y[5]) + m(x[4], y[4]) + m(x5_2, y[3]) + m(x[6], y[2]) + m(x7_2, y[1]) + m(x[8], y[0]) + m(x9_2, y9_19);
//            var z9 = m(x[0], y[9]) + m(x[1], y[8]) + m(x[2], y[7]) + m(x[3], y[6]) + m(x[4], y[5]) + m(x[5], y[4]) + m(x[6], y[3]) + m(x[7], y[2]) + m(x[8], y[1]) + m(x[9], y[0]);

//            // How big is the contribution to z[i+j] from x[i], y[j]?
//            //
//            // Using the bounds above, we get:
//            //
//            // i even, j even:   x[i]*y[j] <   2^(26+b)*2^(26+b) = 2*2^(51+2*b)
//            // i  odd, j even:   x[i]*y[j] <   2^(25+b)*2^(26+b) = 1*2^(51+2*b)
//            // i even, j  odd:   x[i]*y[j] <   2^(26+b)*2^(25+b) = 1*2^(51+2*b)
//            // i  odd, j  odd: 2*x[i]*y[j] < 2*2^(25+b)*2^(25+b) = 1*2^(51+2*b)
//            //
//            // We perform inline reduction mod p by replacing 2^255 by 19
//            // (since 2^255 - 19 = 0 mod p).  This adds a factor of 19, so
//            // we get the bounds (z0 is the biggest one, but calculated for
//            // posterity here in case finer estimation is needed later):
//            //
//            //  z0 < ( 2 + 1*19 + 2*19 + 1*19 + 2*19 + 1*19 + 2*19 + 1*19 + 2*19 + 1*19 )*2^(51 + 2b) = 249*2^(51 + 2*b)
//            //  z1 < ( 1 +  1   + 1*19 + 1*19 + 1*19 + 1*19 + 1*19 + 1*19 + 1*19 + 1*19 )*2^(51 + 2b) = 154*2^(51 + 2*b)
//            //  z2 < ( 2 +  1   +  2   + 1*19 + 2*19 + 1*19 + 2*19 + 1*19 + 2*19 + 1*19 )*2^(51 + 2b) = 195*2^(51 + 2*b)
//            //  z3 < ( 1 +  1   +  1   +  1   + 1*19 + 1*19 + 1*19 + 1*19 + 1*19 + 1*19 )*2^(51 + 2b) = 118*2^(51 + 2*b)
//            //  z4 < ( 2 +  1   +  2   +  1   +  2   + 1*19 + 2*19 + 1*19 + 2*19 + 1*19 )*2^(51 + 2b) = 141*2^(51 + 2*b)
//            //  z5 < ( 1 +  1   +  1   +  1   +  1   +  1   + 1*19 + 1*19 + 1*19 + 1*19 )*2^(51 + 2b) =  82*2^(51 + 2*b)
//            //  z6 < ( 2 +  1   +  2   +  1   +  2   +  1   +  2   + 1*19 + 2*19 + 1*19 )*2^(51 + 2b) =  87*2^(51 + 2*b)
//            //  z7 < ( 1 +  1   +  1   +  1   +  1   +  1   +  1   +  1   + 1*19 + 1*19 )*2^(51 + 2b) =  46*2^(51 + 2*b)
//            //  z6 < ( 2 +  1   +  2   +  1   +  2   +  1   +  2   +  1   +  2   + 1*19 )*2^(51 + 2b) =  33*2^(51 + 2*b)
//            //  z7 < ( 1 +  1   +  1   +  1   +  1   +  1   +  1   +  1   +  1   +  1   )*2^(51 + 2b) =  10*2^(51 + 2*b)
//            //
//            // So z[0] fits into a u64 if 51 + 2*b + lg(249) < 64
//            //                         if b < 2.5.

//            return new[] {(uint) z0, (uint) z1, (uint) z2, (uint) z3, (uint) z4, (uint) z5, (uint) z6, (uint) z7, (uint) z8, (uint) z9};
//        }

//        public override bool Equals(FieldElement fe)
//        {
//            throw new NotImplementedException();
//        }

//        public override void conditional_assign(FieldElement other, bool choice)
//        {
//            throw new NotImplementedException();
//        }

//        public override void conditional_negate(bool choice)
//        {
//            throw new NotImplementedException();
//        }

//        private ulong[] squareInner(uint[] x)
//        {
//            // Optimized version of multiplication for the case of squaring.
//            // Pre- and post- conditions identical to multiplication function.

//            var x0_2 = 2 * x[0];
//            var x1_2 = 2 * x[1];
//            var x2_2 = 2 * x[2];
//            var x3_2 = 2 * x[3];
//            var x4_2 = 2 * x[4];
//            var x5_2 = 2 * x[5];
//            var x6_2 = 2 * x[6];
//            var x7_2 = 2 * x[7];
//            var x5_19 = 19 * x[5];
//            var x6_19 = 19 * x[6];
//            var x7_19 = 19 * x[7];
//            var x8_19 = 19 * x[8];
//            var x9_19 = 19 * x[9];

//            /// Helper function to multiply two 32-bit integers with 64 bits
//            /// of output.
//            ulong m(uint ix, uint iy)
//            {
//                return ix * (ulong) iy;
//            }

//            // This block is rearranged so that instead of doing a 32-bit multiplication by 38, we do a
//            // 64-bit multiplication by 2 on the results.  This is because lg(38) is too big: we would
//            // have less than 1 bit of headroom left, which is too little.
//            var z = new ulong[10];
//            z[0] = m(x[0], x[0]) + m(x2_2, x8_19) + m(x4_2, x6_19) + (m(x1_2, x9_19) + m(x3_2, x7_19) + m(x[5], x5_19)) * 2;
//            z[1] = m(x0_2, x[1]) + m(x3_2, x8_19) + m(x5_2, x6_19) + (m(x[2], x9_19) + m(x[4], x7_19)) * 2;
//            z[2] = m(x0_2, x[2]) + m(x1_2, x[1]) + m(x4_2, x8_19) + m(x[6], x6_19) + (m(x3_2, x9_19) + m(x5_2, x7_19)) * 2;
//            z[3] = m(x0_2, x[3]) + m(x1_2, x[2]) + m(x5_2, x8_19) + (m(x[4], x9_19) + m(x[6], x7_19)) * 2;
//            z[4] = m(x0_2, x[4]) + m(x1_2, x3_2) + m(x[2], x[2]) + m(x6_2, x8_19) + (m(x5_2, x9_19) + m(x[7], x7_19)) * 2;
//            z[5] = m(x0_2, x[5]) + m(x1_2, x[4]) + m(x2_2, x[3]) + m(x7_2, x8_19) + m(x[6], x9_19) * 2;
//            z[6] = m(x0_2, x[6]) + m(x1_2, x5_2) + m(x2_2, x[4]) + m(x3_2, x[3]) + m(x[8], x8_19) + m(x7_2, x9_19) * 2;
//            z[7] = m(x0_2, x[7]) + m(x1_2, x[6]) + m(x2_2, x[5]) + m(x3_2, x[4]) + m(x[8], x9_19) * 2;
//            z[8] = m(x0_2, x[8]) + m(x1_2, x7_2) + m(x2_2, x[6]) + m(x3_2, x5_2) + m(x[4], x[4]) + m(x[9], x9_19) * 2;
//            z[9] = m(x0_2, x[9]) + m(x1_2, x[8]) + m(x2_2, x[7]) + m(x3_2, x[6]) + m(x4_2, x[5]);

//            return z;
//        }

//        /// Compute `self^2`.
//        public override FieldElement square()
//        {
//            var v = squareInner(Value);

//            return new FieldElement32(reduce(v));
//        }

//        ///// Compute `2*self^2`.
//        //pub fn square2(&self) -> FieldElement32 {
//        //    let mut coeffs = self.square_inner();
//        //    for i in 0..self.0.len() {
//        //        coeffs[i] += coeffs[i];
//        //    }
//        //    FieldElement32::reduce(coeffs)
//        //}
//    }
//}