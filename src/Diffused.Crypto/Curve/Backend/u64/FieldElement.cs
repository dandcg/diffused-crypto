using System;
using System.Diagnostics;
using System.Linq;
using Diffused.Crypto.Types;

// ReSharper disable once CheckNamespace
namespace Diffused.Crypto.Curve
{
    /// A `FieldElement64` represents an element of the field
    /// \\( \mathbb Z / (2\^{255} - 19)\\).
    /// 
    /// In the 64-bit implementation, a `FieldElement` is represented in
    /// radix \\(2\^{51}\\) as five `u64`s; the coefficients are allowed to
    /// grow up to \\(2\^{54}\\) between reductions modulo \\(p\\).
    /// 
    /// # Note
    /// 
    /// The `curve25519_dalek::field` module provides a type alias
    /// `curve25519_dalek::field::FieldElement` to either `FieldElement64`
    /// or `FieldElement32`.
    /// 
    /// The backend-specific type `FieldElement64` should not be used
    /// outside of the `curve25519_dalek::field` module.
    public partial struct FieldElement
    {
        private Memory<ulong> value;

        internal FieldElement(ulong[] value)
        {
            this.value = value;
        }

        public override string ToString()
        {
            return $"FieldElement64: {value}";
        }

        // Add

        public static FieldElement operator +(FieldElement lhs, FieldElement rhs)
        {
            return new FieldElement
            {
                value = Add(lhs.value.Span, rhs.value.Span)
            };
        }

        private static ulong[] Add(ReadOnlySpan<ulong> inp, ReadOnlySpan<ulong> rhs)
        {
            var output = inp.ToArray();

            for (var i = 0; i < 5; i++)
            {
                output[i] += rhs[i];
            }

            return output;

        }

        // Sub

        public static FieldElement operator -(FieldElement lhs, FieldElement rhs)
        {
            return new FieldElement
            {
                value = Sub(lhs.value.Span, rhs.value.Span)
            };
        }

        private static ulong[] Sub(ReadOnlySpan<ulong> inp, ReadOnlySpan<ulong> rhs)
        {
            // To avoid underflow, first add a multiple of p.
            // Choose 16*p = p << 4 to be larger than 54-bit _rhs.
            //
            // If we could statically track the bitlengths of the limbs
            // of every FieldElement64, we could choose a multiple of p
            // just bigger than _rhs and avoid having to do a reduction.
            //
            // Since we don't yet have type-level integers to do this, we
            // have to add an explicit reduction call here.

            var sub = new[]
            {
                inp[0] + 36028797018963664 - rhs[0],
                inp[1] + 36028797018963952 - rhs[1],
                inp[2] + 36028797018963952 - rhs[2],
                inp[3] + 36028797018963952 - rhs[3],
                inp[4] + 36028797018963952 - rhs[4]
            };

            reduce(sub);

            return sub;
        }

        // Multiply

        public static FieldElement operator *(FieldElement lhs, FieldElement rhs)
        {
            return new FieldElement
            {
                value = Mul(lhs.value.Span, rhs.value.Span)
            };
        }

        private static ulong[] Mul(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
        {
            // Helper function to multiply two 64-bit integers with 128
            // bits of output.

            UInt128 m(ulong x, ulong y)
            {
                var xu = (UInt128) x;
                var yu = (UInt128) y;
                UInt128.Multiply(out var oti, ref xu, ref yu);
                return oti;
            }

            // Alias self, _rhs for more readable formulas

            // Precondition: assume input limbs a[i], b[i] are bounded as
            //
            // a[i], b[i] < 2^(51 + b)
            //
            // where b is a real parameter measuring the "bit excess" of the limbs.

            // 64-bit pre-computations to avoid 128-bit multiplications.
            //
            // This fits into a u64 whenever 51 + b + lg(19) < 64.
            //
            // Since 51 + b + lg(19) < 51 + 4.25 + b
            //                       = 55.25 + b,
            // this fits if b < 8.75.
            var b1_19 = b[1] * 19;
            var b2_19 = b[2] * 19;
            var b3_19 = b[3] * 19;
            var b4_19 = b[4] * 19;

            // Multiply to get 128-bit coefficients of output
            var c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
            var c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
            var c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
            var c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
            var c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);

            // How big are the c[i]? We have
            //
            //    c[i] < 2^(102 + 2*b) * (1+i + (4-i)*19)
            //         < 2^(102 + lg(1 + 4*19) + 2*b)
            //         < 2^(108.27 + 2*b)
            //
            // The carry (c[i] >> 51) fits into a u64 when
            //    108.27 + 2*b - 51 < 64
            //    2*b < 6.73
            //    b < 3.365.
            //
            // So we require b < 3 to ensure this fits.

            Debug.Assert(a[0] < (ulong) 1 << 54);
            Debug.Assert(b[0] < (ulong) 1 << 54);
            Debug.Assert(a[1] < (ulong) 1 << 54);
            Debug.Assert(b[1] < (ulong) 1 << 54);
            Debug.Assert(a[2] < (ulong) 1 << 54);
            Debug.Assert(b[2] < (ulong) 1 << 54);
            Debug.Assert(a[3] < (ulong) 1 << 54);
            Debug.Assert(b[3] < (ulong) 1 << 54);
            Debug.Assert(a[4] < (ulong) 1 << 54);
            Debug.Assert(b[4] < (ulong) 1 << 54);

            // Casting to u64 and back tells the compiler that the carry is
            // bounded by 2^64, so that the addition is a u128 + u64 rather
            // than u128 + u128.

            const ulong LOW_51_BIT_MASK = ((ulong) 1 << 51) - 1;
            var ot = new ulong[5];

            c1 += c0 >> 51;

            ot[0] = (ulong) c0 & LOW_51_BIT_MASK;

            c2 += c1 >> 51;

            ot[1] = (ulong) c1 & LOW_51_BIT_MASK;

            c3 += c2 >> 51;

            ot[2] = (ulong) c2 & LOW_51_BIT_MASK;

            c4 += c3 >> 51;

            ot[3] = (ulong) c3 & LOW_51_BIT_MASK;

            var carry = (ulong) (c4 >> 51);

            ot[4] = (ulong) c4 & LOW_51_BIT_MASK;

            //Console.WriteLine(c0);
            //Console.WriteLine(c1);
            //Console.WriteLine(c2);
            //Console.WriteLine(c3);
            //Console.WriteLine(c4);

            // To see that this does not overflow, we need out[0] + carry * 19 < 2^64.
            //
            // c4 < a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 + (carry from c3)
            //    < 5*(2^(51 + b) * 2^(51 + b)) + (carry from c3)
            //    < 2^(102 + 2*b + lg(5)) + 2^64.
            //
            // When b < 3 we get
            //
            // c4 < 2^110.33  so that carry < 2^59.33
            //
            // so that
            //
            // out[0] + carry * 19 < 2^51 + 19 * 2^59.33 < 2^63.58
            //
            // and there is no overflow.
            ot[0] = ot[0] + carry * 19;

            // Now out[1] < 2^51 + 2^(64 -51) = 2^51 + 2^13 < 2^(51 + epsilon).
            ot[1] += ot[0] >> 51;
            ot[0] &= LOW_51_BIT_MASK;

            // Now out[i] < 2^(51 + epsilon) for all i.

            return ot;
        }


        public static FieldElement operator -(FieldElement rhs)
        {
            rhs.negate();
            return rhs;
        }


        public void conditional_assign(FieldElement other, bool choice)
        {
    
                if (choice)
                {
                    value = other.value;
                }
     
        }

        public void conditional_negate(bool choice)
        {
       
                if (choice)
                {
                    negate();
                }
       
        }

        /// Invert the sign of this field element
        private void negate()
        {
            var valueSpan = this.value.Span;
            // See commentary in the Sub impl
            var neg = new[]
            {
                36028797018963664 - valueSpan[0],
                36028797018963952 - valueSpan[1],
                36028797018963952 - valueSpan[2],
                36028797018963952 - valueSpan[3],
                36028797018963952 - valueSpan[4]
            };

            reduce(neg);

            this.value = neg.ToArray();
        }

        /// Construct zero.
        public static FieldElement zero()
        {
            return new FieldElement{value = new ulong[5] {0, 0, 0, 0, 0}};
        }

        /// Construct one.
        public static FieldElement one()
        {
            return new FieldElement{value = new ulong[5] {1, 0, 0, 0, 0}};
        }

        /// Construct -1.
        public static FieldElement minus_one()
        {
            return new FieldElement{value = new ulong[5] {2251799813685228, 2251799813685247, 2251799813685247, 2251799813685247, 2251799813685247}};
        }

        /// Given 64-bit input limbs, reduce to enforce the bound 2^(51 + epsilon).
        private static void reduce(Span<ulong> limbs)
        {
            const ulong LOW_51_BIT_MASK = ((ulong) 1 << 51) - 1;

            // Since the input limbs are bounded by 2^64, the biggest
            // carry-out is bounded by 2^13.
            //
            // The biggest carry-in is c4 * 19, resulting in
            //
            // 2^51 + 19*2^13 < 2^51.0000000001
            //
            // Because we don't need to canonicalize, only to reduce the
            // limb sizes, it's OK to do a "weak reduction", where we
            // compute the carry-outs in parallel.

            var c0 = limbs[0] >> 51;
            var c1 = limbs[1] >> 51;
            var c2 = limbs[2] >> 51;
            var c3 = limbs[3] >> 51;
            var c4 = limbs[4] >> 51;

            limbs[0] &= LOW_51_BIT_MASK;
            limbs[1] &= LOW_51_BIT_MASK;
            limbs[2] &= LOW_51_BIT_MASK;
            limbs[3] &= LOW_51_BIT_MASK;
            limbs[4] &= LOW_51_BIT_MASK;

            limbs[0] += c4 * 19;
            limbs[1] += c0;
            limbs[2] += c1;
            limbs[3] += c2;
            limbs[4] += c3;
        }

        // Load a `FieldElement64` from the low 255 bits of a 256-bit
        // input.
        //
        // # Warning
        //
        // This function does not check that the input used the canonical
        // representative.  It masks the high bit, but it will happily
        // decode 2^255 - 18 to 1.  Applications that require a canonical
        // encoding of every field element should decode, re-encode to
        // the canonical encoding, and check that the input was
        // canonical.
        //
        public static FieldElement from_bytes(byte[] bytes)
        {
            ulong Load8(ReadOnlySpan<byte> input)
            {
                return input[0]
                       | ((ulong) input[1] << 8)
                       | ((ulong) input[2] << 16)
                       | ((ulong) input[3] << 24)
                       | ((ulong) input[4] << 32)
                       | ((ulong) input[5] << 40)
                       | ((ulong) input[6] << 48)
                       | ((ulong) input[7] << 56);
            }

            var low_51_bit_mask = ((ulong) 1 << 51) - 1;

            Span<byte> bytesSpan = bytes;

            return new FieldElement
            {
                value = new ulong[5]
                {
                    // load bits [  0, 64), no shift
                    Load8(bytesSpan.Slice(0, 8)) & low_51_bit_mask,
                    // load bits [ 48,112), shift to [ 51,112)
                    (Load8(bytesSpan.Slice(6, 8)) >> 3) & low_51_bit_mask,
                    // load bits [ 96,160), shift to [102,160)
                    (Load8(bytesSpan.Slice(12, 8)) >> 6) & low_51_bit_mask,
                    // load bits [152,216), shift to [153,216)
                    (Load8(bytesSpan.Slice(19, 8)) >> 1) & low_51_bit_mask,
                    // load bits [192,256), shift to [204,112)
                    (Load8(bytesSpan.Slice(24, 8)) >> 12) & low_51_bit_mask
                }
            };
        }

        /// Serialize this `FieldElement64` to a 32-byte array.  The
        /// encoding is canonical.
        public byte[] to_bytes()
        {
            // Let h = limbs[0] + limbs[1]*2^51 + ... + limbs[4]*2^204.
            //
            // Write h = pq + r with 0 <= r < p.
            //
            // We want to compute r = h mod p.
            //
            // If h < 2*p = 2^256 - 38,
            // then q = 0 or 1,
            //
            // with q = 0 when h < p
            //  and q = 1 when h >= p.
            //
            // Notice that h >= p <==> h + 19 >= p + 19 <==> h + 19 >= 2^255.
            // Therefore q can be computed as the carry bit of h + 19.

            // First, reduce the limbs to ensure h < 2*p.
            var limbs = value.ToArray();

            reduce(limbs);

            var q = (limbs[0] + 19) >> 51;
            q = (limbs[1] + q) >> 51;
            q = (limbs[2] + q) >> 51;
            q = (limbs[3] + q) >> 51;
            q = (limbs[4] + q) >> 51;

            // Now we can compute r as r = h - pq = r - (2^255-19)q = r + 19q - 2^255q

            limbs[0] += 19 * q;

            // Now carry the result to compute r + 19q ...
            var low_51_bit_mask = ((ulong) 1 << 51) - 1;
            limbs[1] += limbs[0] >> 51;
            limbs[0] = limbs[0] & low_51_bit_mask;
            limbs[2] += limbs[1] >> 51;
            limbs[1] = limbs[1] & low_51_bit_mask;
            limbs[3] += limbs[2] >> 51;
            limbs[2] = limbs[2] & low_51_bit_mask;
            limbs[4] += limbs[3] >> 51;
            limbs[3] = limbs[3] & low_51_bit_mask;
            // ... but instead of carrying (limbs[4] >> 51) = 2^255q
            // into another limb, discard it, subtracting the value
            limbs[4] = limbs[4] & low_51_bit_mask;

            // Now arrange the bits of the limbs.
            var s = new byte[32];
            s[0] = (byte) (limbs[0] & 0xFF);
            s[1] = (byte) ((limbs[0] >> 8) & 0xFF);
            s[2] = (byte) ((limbs[0] >> 16) & 0xFF);
            s[3] = (byte) ((limbs[0] >> 24) & 0xFF);
            s[4] = (byte) ((limbs[0] >> 32) & 0xFF);
            s[5] = (byte) ((limbs[0] >> 40) & 0xFF);
            s[6] = (byte) (((limbs[0] >> 48) | (limbs[1] << 3)) & 0xFF);
            s[7] = (byte) ((limbs[1] >> 5) & 0xFF);
            s[8] = (byte) ((limbs[1] >> 13) & 0xFF);
            s[9] = (byte) ((limbs[1] >> 21) & 0xFF);
            s[10] = (byte) ((limbs[1] >> 29) & 0xFF);
            s[11] = (byte) ((limbs[1] >> 37) & 0xFF);
            s[12] = (byte) (((limbs[1] >> 45) | (limbs[2] << 6)) & 0xFF);
            s[13] = (byte) ((limbs[2] >> 2) & 0xFF);
            s[14] = (byte) ((limbs[2] >> 10) & 0xFF);
            s[15] = (byte) ((limbs[2] >> 18) & 0xFF);
            s[16] = (byte) ((limbs[2] >> 26) & 0xFF);
            s[17] = (byte) ((limbs[2] >> 34) & 0xFF);
            s[18] = (byte) ((limbs[2] >> 42) & 0xFF);
            s[19] = (byte) (((limbs[2] >> 50) | (limbs[3] << 1)) & 0xFF);
            s[20] = (byte) ((limbs[3] >> 7) & 0xFF);
            s[21] = (byte) ((limbs[3] >> 15) & 0xFF);
            s[22] = (byte) ((limbs[3] >> 23) & 0xFF);
            s[23] = (byte) ((limbs[3] >> 31) & 0xFF);
            s[24] = (byte) ((limbs[3] >> 39) & 0xFF);
            s[25] = (byte) (((limbs[3] >> 47) | (limbs[4] << 4)) & 0xFF);
            s[26] = (byte) ((limbs[4] >> 4) & 0xFF);
            s[27] = (byte) ((limbs[4] >> 12) & 0xFF);
            s[28] = (byte) ((limbs[4] >> 20) & 0xFF);
            s[29] = (byte) ((limbs[4] >> 28) & 0xFF);
            s[30] = (byte) ((limbs[4] >> 36) & 0xFF);
            s[31] = (byte) ((limbs[4] >> 44) & 0xFF);

            // High bit should be zero.
            //--Debug.Assert((s[31] & 0b1000_0000u8) == 0u 8);

            return s;
        }

        public FieldElement pow2k(uint k)
        {
            return new FieldElement(pow2kInternal(k).ToArray());
        }

        /// Given `k > 0`, return `self^(2^k)`.
        private Span<ulong> pow2kInternal(uint k)
        {
            Debug.Assert(k > 0);

            // Multiply two 64-bit integers with 128 bits of output.

            UInt128 M(ulong x, ulong y)
            {
                return (UInt128) x * (UInt128) y;
            }

            Span<ulong> a = value.ToArray();

            do
            {
                // Precondition: assume input limbs a[i] are bounded as
                //
                // a[i] < 2^(51 + b)
                //
                // where b is a real parameter measuring the "bit excess" of the limbs.

                // Precomputation: 64-bit multiply by 19.
                //
                // This fits into a u64 whenever 51 + b + lg(19) < 64.
                //
                // Since 51 + b + lg(19) < 51 + 4.25 + b
                //                       = 55.25 + b,
                // this fits if b < 8.75.
                var a3_19 = 19 * a[3];
                var a4_19 = 19 * a[4];

                // Multiply to get 128-bit coefficients of output.
                //
                // The 128-bit multiplications by 2 turn into 1 slr + 1 slrd each,
                // which doesn't seem any better or worse than doing them as precomputations
                // on the 64-bit inputs.
                var c0 = M(a[0], a[0]) + 2 * (M(a[1], a4_19) + M(a[2], a3_19));
                var c1 = M(a[3], a3_19) + 2 * (M(a[0], a[1]) + M(a[2], a4_19));
                var c2 = M(a[1], a[1]) + 2 * (M(a[0], a[2]) + M(a[4], a3_19));
                var c3 = M(a[4], a4_19) + 2 * (M(a[0], a[3]) + M(a[1], a[2]));
                var c4 = M(a[2], a[2]) + 2 * (M(a[0], a[4]) + M(a[1], a[3]));

                // Same bound as in multiply:
                //    c[i] < 2^(102 + 2*b) * (1+i + (4-i)*19)
                //         < 2^(102 + lg(1 + 4*19) + 2*b)
                //         < 2^(108.27 + 2*b)
                //
                // The carry (c[i] >> 51) fits into a u64 when
                //    108.27 + 2*b - 51 < 64
                //    2*b < 6.73
                //    b < 3.365.
                //
                // So we require b < 3 to ensure this fits.
                //Debug.Assert(a[0] < (1 << 54));
                //Debug.Assert(a[1] < (1 << 54));
                //Debug.Assert(a[2] < (1 << 54));
                //Debug.Assert(a[3] < (1 << 54));
                //Debug.Assert(a[4] < (1 << 54));

                const ulong LOW_51_BIT_MASK = ((ulong) 1 << 51) - 1;

                // Casting to u64 and back tells the compiler that the carry is bounded by 2^64, so
                // that the addition is a u128 + u64 rather than u128 + u128.
                c1 += (ulong) (c0 >> 51);
                a[0] = (ulong) c0 & LOW_51_BIT_MASK;

                c2 += (ulong) (c1 >> 51);
                a[1] = (ulong) c1 & LOW_51_BIT_MASK;

                c3 += (ulong) (c2 >> 51);
                a[2] = (ulong) c2 & LOW_51_BIT_MASK;

                c4 += (ulong) (c3 >> 51);
                a[3] = (ulong) c3 & LOW_51_BIT_MASK;

                var carry = (ulong) (c4 >> 51);
                a[4] = (ulong) c4 & LOW_51_BIT_MASK;

                // To see that this does not overflow, we need a[0] + carry * 19 < 2^64.
                //
                // c4 < a2^2 + 2*a0*a4 + 2*a1*a3 + (carry from c3)
                //    < 2^(102 + 2*b + lg(5)) + 2^64.
                //
                // When b < 3 we get
                //
                // c4 < 2^110.33  so that carry < 2^59.33
                //
                // so that
                //
                // a[0] + carry * 19 < 2^51 + 19 * 2^59.33 < 2^63.58
                //
                // and there is no overflow.
                a[0] = a[0] + carry * 19;

                // Now a[1] < 2^51 + 2^(64 -51) = 2^51 + 2^13 < 2^(51 + epsilon).
                a[1] += a[0] >> 51;
                a[0] &= LOW_51_BIT_MASK;

                // Now all a[i] < 2^(51 + epsilon) and a = self^(2^k).

                k = k - 1;
                if (k == 0)
                {
                    break;
                }
            } while (true);

            return a;
        }

        /// Returns the square of this field element.
        public FieldElement square()
        {
            return new FieldElement(pow2kInternal(1).ToArray());
        }

        /// Returns 2 times the square of this field element.
        public FieldElement square2()
        {
            var square = pow2kInternal(1);

            for (var i = 0; i < 5; i++)
            {
                square[i] *= 2;
            }

            return new FieldElement(square.ToArray());
        }
    }
}