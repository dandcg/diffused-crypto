using System;
using Diffused.Crypto.Architecture.x64;

namespace Diffused.Crypto.Architecture
{
    public abstract class FieldElement
    {
        /// Invert the sign of this field element
        public abstract void negate();

        /// Construct zero.
        public abstract void zero();

        /// Construct one.
        public abstract void one();

        /// Construct -1.
        public abstract void minus_one();

        public abstract void from_bytes(byte[] bytes);

        /// Serialize this `FieldElement64` to a 32-byte array.  The
        /// encoding is canonical.
        public abstract byte[] to_bytes();

        /// Returns the square of this field element.
        public abstract FieldElement square();

        public abstract FieldElement pow2k(uint k);

        public abstract FieldElement Mul(FieldElement rhs);

        /// Determine if this `FieldElement` is negative, in the sense
        /// used in the ed25519 paper: `x` is negative if the low bit is
        /// set.
        /// 
        /// # Return
        /// 
        /// If negative, return `Choice(1)`.  Otherwise, return `Choice(0)`.
        public bool is_negative()
        {
            var bytes = to_bytes();
            return Convert.ToBoolean(bytes[0] & 1);
        }

        /// Determine if this `FieldElement` is zero.
        /// 
        /// # Return
        /// 
        /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
        public bool is_zero()
        {
            return Array.TrueForAll(to_bytes(), w => w == 0);
        }

        /// Compute (self^(2^250-1), self^11), used as a helper function
        /// within invert() and pow22523().
        public (FieldElement fe1, FieldElement fe2) pow22501()
        {
            // Instead of managing which temporary variables are used
            // for what, we define as many as we need and leave stack
            // allocation to the compiler
            //
            // Each temporary variable t_i is of the form (self)^e_i.
            // Squaring t_i corresponds to multiplying e_i by 2,
            // so the pow2k function shifts e_i left by k places.
            // Multiplying t_i and t_j corresponds to adding e_i + e_j.
            //
            // Temporary t_i                      Nonzero bits of e_i
            //
            var t0 = this.square(); // 1         e_0 = 2^1
            var t1 = t0.square().square(); // 3         e_1 = 2^3
            var t2 = this.Mul(t1); // 3,0       e_2 = 2^3 + 2^0
            var t3 = t0.Mul(t2); // 3,1,0
            var t4 = t3.square(); // 4,2,1
            var t5 = t2.Mul(t4); // 4,3,2,1,0
            var t6 = t5.pow2k(5); // 9,8,7,6,5
            var t7 = t6.Mul(t5); // 9,8,7,6,5,4,3,2,1,0
            var t8 = t7.pow2k(10); // 19..10
            var t9 = t8.Mul(t7); // 19..0
            var t10 = t9.pow2k(20); // 39..20
            var t11 = t10.Mul(t9); // 39..0
            var t12 = t11.pow2k(10); // 49..10
            var t13 = t12.Mul(t7); // 49..0
            var t14 = t13.pow2k(50); // 99..50
            var t15 = t14.Mul(t13); // 99..0
            var t16 = t15.pow2k(100); // 199..100
            var t17 = t16.Mul(t15); // 199..0
            var t18 = t17.pow2k(50); // 249..50
            var t19 = t18.Mul(t13); // 249..0

            return (t19, t3);
        }

        // Given a slice of public `FieldElements`, replace each with its inverse.
        //
        // All input `FieldElements` **MUST** be nonzero.

        public void batch_invert(FieldElement[] inputs)
        {
            // Montgomery’s Trick and Fast Implementation of Masked AES
            // Genelle, Prouff and Quisquater
            // Section 3.2

            var n = inputs.Length;
            var scratch = new FieldElement[n];

            Array.ForEach(scratch, e =>
            {
                e = new FieldElement64();
                e.one();
            });

            // Keep an accumulator of all of the previous products
            FieldElement acc = new FieldElement64();
            acc.one();

            // Pass through the input vector, recording the previous
            // products in the scratch space
            for (int i = 0; i < n; i++)
            {
                scratch[i] = acc;
                acc = acc.Mul(inputs[i]);
            }

            // Compute the inverse of all products
            acc = acc.invert();

            // Pass through the vector backwards to compute the inverses
            // in place
            // Pass through the input vector, recording the previous
            // products in the scratch space
            for (int i = n - 1; i >= 0; i--)
            {
                var tmp = acc.Mul(inputs[i]);
                inputs[i] = acc.Mul(scratch[i]);
                acc = tmp;
            }
        }

        /// Given a nonzero field element, compute its inverse.
        /// 
        /// The inverse is computed as self^(p-2), since
        /// x^(p-2)x = x^(p-1) = 1 (mod p).
        /// 
        /// This function returns zero on input zero.
        public FieldElement invert()
        {
            // The bits of p-2 = 2^255 -19 -2 are 11010111111...11.
            //
            // nonzero bits of exponent
            var (t19, t3) = pow22501(); // t19: 249..0 ; t3: 3,1,0
            var t20 = t19.pow2k(5); // 254..5
            var t21 = t20.Mul(t3); // 254..5,3,1,0

            return t21;
        }

        // Raise this field element to the power (p-5)/8 = 2^252 -3.
        public FieldElement pow_p58()
        {
            // The bits of (p-5)/8 are 101111.....11.
            //
            //                                 nonzero bits of exponent
            var (t19, _) = pow22501(); // 249..0
            var t20 = t19.pow2k(2); // 251..2
            var t21 = Mul(t20); // 251..2,0

            return t21;
        }

        //Given `FieldElements` `u` and `v`, attempt to compute
        // `sqrt(u/v)` in constant time.

        // This function always returns the nonnegative square root, if it exists.


        // It would be much better to use an `Option` type here, but
        // doing so forces the caller to branch, which we don't want to
        // do.  This seems like the least bad solution.
        
        // # Return
        
        // - `(1u8, sqrt(u/v))` if `v` is nonzero and `u/v` is square;
        // - `(0u8, zero)`      if `v` is zero;
        // - `(0u8, garbage)`   if `u/v` is nonsquare.
        
        // # Example
        
        // ```ignore
        // let one = FieldElement::one();
        // let two = &one + &one;
        //let four = &two * &two;

        //// two is nonsquare mod p
        //let(two_is_square, two_sqrt) = FieldElement::sqrt_ratio(&two, &one);
        // assert_eq!(two_is_square.unwrap_u8(), 0u8);
        
        // // four is square mod p
        // let(four_is_square, four_sqrt) = FieldElement::sqrt_ratio(&four, &one);
        
        // assert_eq!(four_is_square.unwrap_u8(), 1u8);
        // assert_eq!(four_sqrt.is_negative().unwrap_u8
        // ```
        
        //public (bool choice, FieldElement fe) sqrt_ratio(FieldElement u, FieldElement v)
        //{
        //    // Using the same trick as in ed25519 decoding, we merge the
        //    // inversion, the square root, and the square test as follows.
        //    //
        //    // To compute sqrt(α), we can compute β = α^((p+3)/8).
        //    // Then β^2 = ±α, so multiplying β by sqrt(-1) if necessary
        //    // gives sqrt(α).
        //    //
        //    // To compute 1/sqrt(α), we observe that
        //    //    1/β = α^(p-1 - (p+3)/8) = α^((7p-11)/8)
        //    //                            = α^3 * (α^7)^((p-5)/8).
        //    //
        //    // We can therefore compute sqrt(u/v) = sqrt(u)/sqrt(v)
        //    // by first computing
        //    //    r = u^((p+3)/8) v^(p-1-(p+3)/8)
        //    //      = u u^((p-5)/8) v^3 (v^7)^((p-5)/8)
        //    //      = (uv^3) (uv^7)^((p-5)/8).
        //    //
        //    // If v is nonzero and u/v is square, then r^2 = ±u/v,
        //    //                                     so vr^2 = ±u.
        //    // If vr^2 =  u, then sqrt(u/v) = r.
        //    // If vr^2 = -u, then sqrt(u/v) = r*sqrt(-1).
        //    //
        //    // If v is zero, r is also zero.

        //    var v3 = v.square().Mul(v);
        //    var v7 = v3.square().Mul(v);
        //    var r = (u.Mul(v3).Mul(u.Mul(v7)).pow_p58());
        //    var check = v.Mul(r.square());

        //    var correct_sign_sqrt = check.Equals(u);
        //    var flipped_sign_sqrt = check.Equals(-u);

        //    var r_prime = &constants::SQRT_M1 * &r;
        //    r.conditional_assign(&r_prime, flipped_sign_sqrt);

        //    // Choose the nonnegative square root.
        //    var r_is_negative = r.is_negative();
        //    r.conditional_negate(r_is_negative);

        //    var was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;

        //    return (was_nonzero_square, r);
        //}

        // For `self` a nonzero square, compute 1/sqrt(self) in
        // constant time.
        //
        // It would be much better to use an `Option` type here, but
        // doing so forces the caller to branch, which we don't want to
        // do.  This seems like the least bad solution.
        //
        // # Return
        //
        // - `(1u8, 1/sqrt(self))` if `self` is a nonzero square;
        // - `(0u8, zero)`         if `self` is zero;
        // - `(0u8, garbage)`      if `self` is nonsquare.
        //
        //public (bool choice, FieldElement fe) invsqrt()
        //{
        //    var fe=new FieldElement64();
        //    fe.one();
        //    return sqrt_ratio(fe, this);
        //}

        // chi calculates `self^((p-1)/2)`.
        // 
        // # Return
        // 
        // * If this element is a non-zero square, returns `1`.
        // * If it is zero, returns `0`.
        // * If it is non-square, returns `-1`.
        public FieldElement chi()

        {
            // extra25519.chi
            // The bits of (p-1)/2 = 2^254 -10 are 0110111111...11.
            //
            //                                 nonzero bits of exponent
            var (t19, _) = pow22501(); // 249..0
            var t20 = t19.pow2k(4); // 253..4
            var t21 = square(); // 1
            var t22 = t21.square(); // 2
            var t23 = t22.Mul(t21); // 2,1
            var t24 = t20.Mul(t23); // 253..4,2,1

            return t24;
        }

        public abstract bool Equals(FieldElement fe);
        public abstract void conditional_assign(FieldElement other, bool choice);
        public abstract void conditional_negate(bool choice);


        


    }
}