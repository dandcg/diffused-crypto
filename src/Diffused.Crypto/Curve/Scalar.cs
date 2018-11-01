using System;
using System.Diagnostics;
using System.Linq;

namespace Diffused.Crypto.Curve
{
    //! Arithmetic on scalars (integers mod the group order).
    //!
    //! Both the Ristretto group and the Ed25519 basepoint have prime order
    //! \\( \ell = 2\^{252} + 27742317777372353535851937790883648493 \\).
    //!
    //! This code is intended to be useful with both the Ristretto group
    //! (where everything is done modulo \\( \ell \\)), and the X/Ed25519
    //! setting, which mandates specific bit-twiddles that are not
    //! well-defined modulo \\( \ell \\).
    //!
    //! All arithmetic on `Scalars` is done modulo \\( \ell \\).
    //!
    //! # Constructing a scalar
    //!
    //! To create a [`Scalar`](struct.Scalar.html) from a supposedly canonical encoding, use
    //! [`Scalar::from_canonical_bytes`](struct.Scalar.html#method.from_canonical_bytes).
    //!
    //! This function does input validation, ensuring that the input bytes
    //! are the canonical encoding of a `Scalar`.
    //! If they are, we'll get
    //! `Some(Scalar)` in return:
    //!
    //! ```
    //! use curve25519_dalek::scalar::Scalar;
    //!
    //! let one_as_bytes: [u8; 32] = Scalar::one().to_bytes();
    //! let a: Option<Scalar> = Scalar::from_canonical_bytes(one_as_bytes);
    //!
    //! assert!(a.is_some());
    //! ```
    //!
    //! However, if we give it bytes representing a scalar larger than \\( \ell \\)
    //! (in this case, \\( \ell + 2 \\)), we'll get `None` back:
    //!
    //! ```
    //! use curve25519_dalek::scalar::Scalar;
    //!
    //! let l_plus_two_bytes: [u8; 32] = [
    //!    0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    //!    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    //!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    //! ];
    //! let a: Option<Scalar> = Scalar::from_canonical_bytes(l_plus_two_bytes);
    //!
    //! assert!(a.is_none());
    //! ```
    //!
    //! Another way to create a `Scalar` is by reducing a \\(256\\)-bit integer mod
    //! \\( \ell \\), for which one may use the
    //! [`Scalar::from_bytes_mod_order`](struct.Scalar.html#method.from_bytes_mod_order)
    //! method.  In the case of the second example above, this would reduce the
    //! resultant scalar \\( \mod \ell \\), producing \\( 2 \\):
    //!
    //! ```
    //! use curve25519_dalek::scalar::Scalar;
    //!
    //! let l_plus_two_bytes: [u8; 32] = [
    //!    0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    //!    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    //!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    //! ];
    //! let a: Scalar = Scalar::from_bytes_mod_order(l_plus_two_bytes);
    //!
    //! let two: Scalar = Scalar::one() + Scalar::one();
    //!
    //! assert!(a == two);
    //! ```
    //!
    //! There is also a constructor that reduces a \\(512\\)-bit integer, 
    //! [`Scalar::from_bytes_mod_order_wide`](struct.Scalar.html#method.from_bytes_mod_order_wide).
    //!
    //! To construct a `Scalar` as the hash of some input data, use 
    //! [`Scalar::hash_from_bytes`](struct.Scalar.html#method.hash_from_bytes),
    //! which takes a buffer, or
    //! [`Scalar::from_hash`](struct.Scalar.html#method.from_hash),
    //! which allows an IUF API.
    //!
    //! ```
    //! # extern crate curve25519_dalek;
    //! # extern crate sha2;
    //! #
    //! # fn main() {
    //! use sha2::{Digest, Sha512};
    //! use curve25519_dalek::scalar::Scalar;
    //!
    //! // Hashing a single byte slice
    //! let a = Scalar::hash_from_bytes::<Sha512>(b"Abolish ICE");
    //!
    //! // Streaming data into a hash object
    //! let mut hasher = Sha512::default();
    //! hasher.input(b"Abolish ");
    //! hasher.input(b"ICE");
    //! let a2 = Scalar::from_hash(hasher);
    //!
    //! assert_eq!(a, a2);
    //! # }
    //! ```
    //!
    //! Finally, to create a `Scalar` with a specific bit-pattern
    //! (e.g., for compatibility with X/Ed25519
    //! ["clamping"](https://github.com/isislovecruft/ed25519-dalek/blob/f790bd2ce/src/ed25519.rs#L349)),
    //! use [`Scalar::from_bits`](struct.Scalar.html#method.from_bits). This
    //! constructs a scalar with exactly the bit pattern given, without any
    //! assurances as to reduction modulo the group order:
    //!
    //! ```
    //! use curve25519_dalek::scalar::Scalar;
    //!
    //! let l_plus_two_bytes: [u8; 32] = [
    //!    0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    //!    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    //!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //!    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    //! ];
    //! let a: Scalar = Scalar::from_bits(l_plus_two_bytes);
    //!
    //! let two: Scalar = Scalar::one() + Scalar::one();
    //!
    //! assert!(a != two);              // the scalar is not reduced (mod l)…
    //! assert!(! a.is_canonical());    // …and therefore is not canonical.
    //! assert!(a.reduce() == two);     // if we were to reduce it manually, it would be.
    //! ```
    //!
    //! The resulting `Scalar` has exactly the specified bit pattern,
    //! **except for the highest bit, which will be set to 0**.
    public struct Scalar
    {

        public Scalar(byte[] bytes)
        {
            this.bytes = bytes;
        }

        public override string ToString()
        {
            return $"Scalar: {string.Join(", ", bytes.ToArray())}";
        }

        /// `bytes` is a little-endian byte encoding of an integer representing a scalar modulo the
        /// group order.
        /// 
        /// # Invariant
        /// 
        /// The integer representing this scalar must be bounded above by \\(2\^{255}\\), or
        /// equivalently the high bit of `bytes[31]` must be zero.
        /// 
        /// This ensures that there is room for a carry bit when computing a NAF representation.
        //
        // XXX This is pub(crate) so we can write literal constants.  If const fns were stable, we could
        //     make the Scalar constructors const fns and use those instead.
        private Memory<byte> bytes;

        public Span<byte> Value => bytes.Span;

        /// Construct a `Scalar` by reducing a 256-bit little-endian integer
        /// modulo the group order \\( \ell \\).
        public static Scalar from_bytes_mod_order(byte[] bytes)
        {
            // Temporarily allow s_unreduced.bytes > 2^255 ...
            var s_unreduced = new Scalar {bytes = bytes};

            // Then reduce mod the group order and return the reduced representative.
            var s = s_unreduced.reduce();
            Debug.Assert(0 == s.bytes.Span[31] >> 7);

            return s;
        }

        /// Construct a `Scalar` by reducing a 512-bit little-endian integer
        /// modulo the group order \\( \ell \\).
        public static Scalar from_bytes_mod_order_wide(byte[] input)
        {
            return UnpackedScalar.from_bytes_wide(input).pack();
        }

        /// Attempt to construct a `Scalar` from a canonical byte representation.
        /// 
        /// # Return
        /// 
        /// - `Some(s)`, where `s` is the `Scalar` corresponding to `bytes`,
        /// if `bytes` is a canonical byte representation;
        /// - `None` if `bytes` is not a canonical byte representation.
        public static Scalar? from_canonical_bytes(byte[] bytes)
        {
            // Check that the high bit is not set
            if (bytes[31] >> 7 != 0)
            {
                return null;
            }

            var candidate = from_bits(bytes);

            if (candidate.is_canonical())
            {
                return candidate;
            }

            return null;
        }

        /// Construct a `Scalar` from the low 255 bits of a 256-bit integer.
        /// 
        /// This function is intended for applications like X25519 which
        /// require specific bit-patterns when performing scalar
        /// multiplication.
        public static Scalar from_bits(byte[] bytes)
        {
            var s = new Scalar {bytes = bytes};
            // Ensure that s < 2^255 by masking the high bit
            var spanBytes = s.bytes.Span;
            spanBytes[31] &= 0b0111_1111;
            return s;
        }

        // Multiply

        public static Scalar operator *(Scalar lhs, Scalar rhs)
        {
            return UnpackedScalar.mul(lhs.unpack(), rhs.unpack()).pack();
        }

        // Add

        public static Scalar operator +(Scalar lhs, Scalar rhs)
        {
            return UnpackedScalar.add(lhs.unpack(), rhs.unpack()).pack();
        }

        // Sub

        public static Scalar operator -(Scalar lhs, Scalar rhs)
        {
            return UnpackedScalar.sub(lhs.unpack(), rhs.unpack()).pack();
        }

        public static Scalar operator -(Scalar rhs)
        {
            return UnpackedScalar.sub(Scalar.one().unpack(), rhs.unpack()).pack();
        }
        //impl From<u8> for Scalar {
        //    fn from(x: u8) -> Scalar {
        //        let mut s_bytes = [0u8; 32];
        //        s_bytes[0] = x;
        //        Scalar{ bytes: s_bytes }
        //    }
        //}

        //impl From<u16> for Scalar {
        //    fn from(x: u16) -> Scalar {
        //        use byteorder::{ByteOrder, LittleEndian};
        //        let mut s_bytes = [0u8; 32];
        //        LittleEndian::write_u16(&mut s_bytes, x);
        //        Scalar{ bytes: s_bytes }
        //    }
        //}


        public static Scalar from(uint x)
        {

            Span<byte> s_bytes = new byte[32];
            BitConverter.GetBytes(x).CopyTo(s_bytes);
            
            if (!BitConverter.IsLittleEndian)
            {
                s_bytes.Reverse();
                
            }
            
            return new Scalar {bytes = s_bytes.ToArray()};
            }



            /// Construct a scalar from the given `u64`.
            ///
            /// # Inputs
            ///
            /// An `u64` to convert to a `Scalar`.
            ///
            /// # Returns
            ///
            /// A `Scalar` corresponding to the input `u64`.
            ///
            /// # Example
            ///
            /// ```
            /// use curve25519_dalek::scalar::Scalar;
            ///
            /// let fourtytwo = Scalar::from(42u64);
            /// let six = Scalar::from(6u64);
            /// let seven = Scalar::from(7u64);
            ///
            /// assert!(fourtytwo == six * seven);
            /// ```
            public static Scalar from(ulong x)
        {

            Span<byte> s_bytes = new byte[32];
            BitConverter.GetBytes(x).CopyTo(s_bytes);
            
            if (!BitConverter.IsLittleEndian)
            {
                s_bytes.Reverse();
                
            }
            
            return new Scalar {bytes = s_bytes.ToArray()};
        }

        //impl From<u128> for Scalar {
        //    fn from(x: u128) -> Scalar {
        //        use byteorder::{ByteOrder, LittleEndian};
        //        let mut s_bytes = [0u8; 32];
        //        LittleEndian::write_u128(&mut s_bytes, x);
        //        Scalar{ bytes: s_bytes }
        //    }
        //}









        //-------------------------------------------------------------------------------

        //      /// Return a `Scalar` chosen uniformly at random using a user-provided RNG.
        /////
        ///// # Inputs
        /////
        ///// * `rng`: any RNG which implements the `rand::CryptoRng` interface.
        /////
        ///// # Returns
        /////
        ///// A random scalar within ℤ/lℤ.
        /////
        ///// # Example
        /////
        ///// ```
        ///// extern crate rand;
        ///// # extern crate curve25519_dalek;
        ///// #
        ///// # fn main() {
        ///// use curve25519_dalek::scalar::Scalar;
        /////
        ///// use rand::OsRng;
        /////
        ///// let mut csprng: OsRng = OsRng::new().unwrap();
        ///// let a: Scalar = Scalar::random(&mut csprng);
        ///// # }
        //pub fn random<T: Rng + CryptoRng>(rng: &mut T) -> Self {
        //    let mut scalar_bytes = [0u8; 64];
        //    rng.fill(&mut scalar_bytes);
        //    Scalar::from_bytes_mod_order_wide(&scalar_bytes)
        //}

        ///// Hash a slice of bytes into a scalar.
        /////
        ///// Takes a type parameter `D`, which is any `Digest` producing 64
        ///// bytes (512 bits) of output.
        /////
        ///// Convenience wrapper around `from_hash`.
        /////
        ///// # Example
        /////
        ///// ```
        ///// # extern crate curve25519_dalek;
        ///// # use curve25519_dalek::scalar::Scalar;
        ///// extern crate sha2;
        /////
        ///// use sha2::Sha512;
        /////
        ///// # // Need fn main() here in comment so the doctest compiles
        ///// # // See https://doc.rust-lang.org/book/documentation.html#documentation-as-tests
        ///// # fn main() {
        ///// let msg = "To really appreciate architecture, you may even need to commit a murder";
        ///// let s = Scalar::hash_from_bytes::<Sha512>(msg.as_bytes());
        ///// # }
        ///// ```
        //pub fn hash_from_bytes<D>(input: &[u8]) -> Scalar
        //    where D: Digest<OutputSize = U64> + Default
        //{
        //    let mut hash = D::default();
        //    hash.input(input);
        //    Scalar::from_hash(hash)
        //}

        ///// Construct a scalar from an existing `Digest` instance.
        /////
        ///// Use this instead of `hash_from_bytes` if it is more convenient
        ///// to stream data into the `Digest` than to pass a single byte
        ///// slice.
        /////
        ///// # Example
        /////
        ///// ```
        ///// # extern crate curve25519_dalek;
        ///// # use curve25519_dalek::scalar::Scalar;
        ///// extern crate sha2;
        /////
        ///// use sha2::Digest;
        ///// use sha2::Sha512;
        /////
        ///// # fn main() {
        ///// let mut h = Sha512::default();
        /////
        ///// h.input(b"To really appreciate architecture, you may even need to commit a murder.");
        ///// h.input(b"While the programs used for The Manhattan Transcripts are of the most extreme");
        ///// h.input(b"nature, they also parallel the most common formula plot: the archetype of");
        ///// h.input(b"murder. Other phantasms were occasionally used to underline the fact that");
        ///// h.input(b"perhaps all architecture, rather than being about functional standards, is");
        ///// h.input(b"about love and death.");
        /////
        ///// let s = Scalar::from_hash(h);
        /////
        ///// println!("{:?}", s.to_bytes());
        ///// assert!(s == Scalar::from_bits([ 21,  88, 208, 252,  63, 122, 210, 152,
        /////                                 154,  38,  15,  23,  16, 167,  80, 150,
        /////                                 192, 221,  77, 226,  62,  25, 224, 148,
        /////                                 239,  48, 176,  10, 185,  69, 168,  11, ]));
        ///// # }
        ///// ```
        //pub fn from_hash<D>(hash: D) -> Scalar
        //    where D: Digest<OutputSize = U64> + Default
        //{
        //    let mut output = [0u8; 64];
        //    output.copy_from_slice(hash.result().as_slice());
        //    Scalar::from_bytes_mod_order_wide(&output)
        //}

        ///// Convert this `Scalar` to its underlying sequence of bytes.
        /////
        ///// # Example
        /////
        ///// ```
        ///// use curve25519_dalek::scalar::Scalar;
        /////
        ///// let s: Scalar = Scalar::zero();
        /////
        ///// assert!(s.to_bytes() == [0u8; 32]);
        ///// ```
        //pub fn to_bytes(&self) -> [u8; 32] {
        //    self.bytes
        //}

        ///// View the little-endian byte encoding of the integer representing this Scalar.
        /////
        ///// # Example
        /////
        ///// ```
        ///// use curve25519_dalek::scalar::Scalar;
        /////
        ///// let s: Scalar = Scalar::zero();
        /////
        ///// assert!(s.as_bytes() == &[0u8; 32]);
        ///// ```
        //pub fn as_bytes(&self) -> &[u8; 32] {
        //    &self.bytes
        //}

        /// Construct the scalar \\( 0 \\).
        public static Scalar zero()
        {
            return new Scalar(new byte[32]);
        }


/// Construct the scalar \\( 1 \\).
public static Scalar one()
        {
            return new Scalar
            {
                bytes = new byte[]
                {
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                }
            };
        }

        ///// Given a nonzero `Scalar`, compute its multiplicative inverse.
        /////
        ///// # Warning
        /////
        ///// `self` **MUST** be nonzero.  If you cannot
        ///// *prove* that this is the case, you **SHOULD NOT USE THIS
        ///// FUNCTION**.
        /////
        ///// # Returns
        /////
        ///// The multiplicative inverse of the this `Scalar`.
        /////
        ///// # Example
        /////
        ///// ```
        ///// use curve25519_dalek::scalar::Scalar;
        /////
        ///// // x = 2238329342913194256032495932344128051776374960164957527413114840482143558222
        ///// let X: Scalar = Scalar::from_bytes_mod_order([
        /////         0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84,
        /////         0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2, 0x7d, 0x52,
        /////         0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44,
        /////         0xd4, 0x49, 0xf4, 0xa8, 0x79, 0xd9, 0xf2, 0x04,
        /////     ]);
        ///// // 1/x = 6859937278830797291664592131120606308688036382723378951768035303146619657244
        ///// let XINV: Scalar = Scalar::from_bytes_mod_order([
        /////         0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb,
        /////         0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01, 0x63, 0x47,
        /////         0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96,
        /////         0xd5, 0x0b, 0xcd, 0x7a, 0x3f, 0x96, 0x2a, 0x0f,
        /////     ]);
        /////
        ///// let inv_X: Scalar = X.invert();
        ///// assert!(XINV == inv_X);
        ///// let should_be_one: Scalar = &inv_X * &X;
        ///// assert!(should_be_one == Scalar::one());
        ///// ```
      public Scalar invert()
      {
        return unpack().invert().pack();
      }

        ///// Given a slice of nonzero (possibly secret) `Scalar`s,
        ///// compute their inverses in a batch.
        /////
        ///// # Return
        /////
        ///// Each element of `inputs` is replaced by its inverse.
        /////
        ///// The product of all inverses is returned.
        /////
        ///// # Warning
        /////
        ///// All input `Scalars` **MUST** be nonzero.  If you cannot
        ///// *prove* that this is the case, you **SHOULD NOT USE THIS
        ///// FUNCTION**.
        /////
        ///// # Example
        /////
        ///// ```
        ///// # extern crate curve25519_dalek;
        ///// # use curve25519_dalek::scalar::Scalar;
        ///// # fn main() {
        ///// let mut scalars = [
        /////     Scalar::from(3u64),
        /////     Scalar::from(5u64),
        /////     Scalar::from(7u64),
        /////     Scalar::from(11u64),
        ///// ];
        /////
        ///// let allinv = Scalar::batch_invert(&mut scalars);
        /////
        ///// assert_eq!(allinv, Scalar::from(3*5*7*11u64).invert());
        ///// assert_eq!(scalars[0], Scalar::from(3u64).invert());
        ///// assert_eq!(scalars[1], Scalar::from(5u64).invert());
        ///// assert_eq!(scalars[2], Scalar::from(7u64).invert());
        ///// assert_eq!(scalars[3], Scalar::from(11u64).invert());
        ///// # }
        ///// ```

       public static Scalar batch_invert(Scalar[] inputs) 
       {
        // This code is essentially identical to the FieldElement
        // implementation, and is documented there.  Unfortunately,
        // it's not easy to write it generically, since here we want
        // to use `UnpackedScalar`s internally, and `Scalar`s
        // externally, but there's no corresponding distinction for
        // field elements.

        //use clear_on_drop::ClearOnDrop;
        //use clear_on_drop::clear::ZeroSafe;
        // Mark UnpackedScalars as zeroable.
        //unsafe impl ZeroSafe for UnpackedScalar {}

   var n = inputs.Length;
           var one= Scalar.one().unpack().to_montgomery();

    // Wrap the scratch storage in a ClearOnDrop to wipe it when
    // we pass out of scope.
           Span<Scalar> scratch_vec = new Scalar[n];
           scratch_vec.Fill(Scalar.one());
           

        // Keep an accumulator of all of the previous products
        var acc = Scalar.one().unpack().to_montgomery();

        // Pass through the input vector, recording the previous
        // products in the scratch space

           for (int i = 0; i < n; i++)
           {
               var input = scratch_vec[n];
               //scratch = acc;

               // Avoid unnecessary Montgomery multiplication in second pass by
               // keeping inputs in Montgomery form
               var tmp = input.unpack().to_montgomery();
               input = tmp.pack();
               acc = UnpackedScalar.montgomery_mul(acc, tmp);
           }



    // acc is nonzero iff all inputs are nonzero
    Debug.Assert(acc.pack() != Scalar.zero());

        // Compute the inverse of all products
        acc = acc.montgomery_invert().from_montgomery();

    // We need to return the product of all inverses later
 var ret = acc.pack();

        // Pass through the vector backwards to compute the inverses
        // in place

           for (int i = 0; i < n; i++)
           {
               var scratch = scratch_vec[n];
               var input = inputs[n];
             var tmp = UnpackedScalar.montgomery_mul(acc, input.unpack());
               input = UnpackedScalar.montgomery_mul(acc, scratch.unpack()).pack();
               acc = tmp;
           }



           return ret;
       }

///// Get the bits of the scalar.
//pub(crate) fn bits(&self) -> [i8; 256] {
//    let mut bits = [0i8; 256];
//    for i in 0..256 {
//        // As i runs from 0..256, the bottom 3 bits index the bit,
//        // while the upper bits index the byte.
//        bits[i] = ((self.bytes[i>>3] >> (i&7)) & 1u8) as i8;
//    }
//    bits
//}

// Compute a width-\\(w\\) "Non-Adjacent Form" of this scalar.
//
// A width-\\(w\\) NAF of a positive integer \\(k\\) is an expression
// $$
// k = \sum_{i=0}\^m n\_i 2\^i,
// $$
// where each nonzero
// coefficient \\(n\_i\\) is odd and bounded by \\(|n\_i| < 2\^{w-1}\\),
// \\(n\_{m-1}\\) is nonzero, and at most one of any \\(w\\) consecutive
// coefficients is nonzero.  (Hankerson, Menezes, Vanstone; def 3.32).
//
// The length of the NAF is at most one more than the length of
// the binary representation of \\(k\\).  This is why the
// `Scalar` type maintains an invariant that the top bit is
// \\(0\\), so that the NAF of a scalar has at most 256 digits.
//
// Intuitively, this is like a binary expansion, except that we
// allow some coefficients to grow in magnitude up to
// \\(2\^{w-1}\\) so that the nonzero coefficients are as sparse
// as possible.
//
// When doing scalar multiplication, we can then use a lookup
// table of precomputed multiples of a point to add the nonzero
// terms \\( k_i P \\).  Using signed digits cuts the table size
// in half, and using odd digits cuts the table size in half
// again.
//
// To compute a \\(w\\)-NAF, we use a modification of Algorithm 3.35 of HMV:
//
// 1. \\( i \gets 0 \\)
// 2. While \\( k \ge 1 \\):
//     1. If \\(k\\) is odd, \\( n_i \gets k \operatorname{mods} 2^w \\), \\( k \gets k - n_i \\).
//     2. If \\(k\\) is even, \\( n_i \gets 0 \\).
//     3. \\( k \gets k / 2 \\), \\( i \gets i + 1 \\).
// 3. Return \\( n_0, n_1, ... , \\)
//
// Here \\( \bar x = x \operatorname{mods} 2^w \\) means the
// \\( \bar x \\) with \\( \bar x \equiv x \pmod{2^w} \\) and
// \\( -2^{w-1} \leq \bar x < 2^w \\).
//
// We implement this by scanning across the bits of \\(k\\) from
// least-significant bit to most-significant-bit.
// Write the bits of \\(k\\) as
// $$
// k = \sum\_{i=0}\^m k\_i 2^i,
// $$
// and split the sum as
// $$
// k = \sum\_{i=0}^{w-1} k\_i 2^i + 2^w \sum\_{i=0} k\_{i+w} 2^i
// $$
// where the first part is \\( k \mod 2^w \\).
//
// If \\( k \mod 2^w\\) is odd, and \\( k \mod 2^w < 2^{w-1} \\), then we emit
// \\( n_0 = k \mod 2^w \\).  Instead of computing
// \\( k - n_0 \\), we just advance \\(w\\) bits and reindex.
//
// If \\( k \mod 2^w\\) is odd, and \\( k \mod 2^w \ge 2^{w-1} \\), then
// \\( n_0 = k \operatorname{mods} 2^w = k \mod 2^w - 2^w \\).
// The quantity \\( k - n_0 \\) is
// $$
// \begin{aligned}
// k - n_0 &= \sum\_{i=0}^{w-1} k\_i 2^i + 2^w \sum\_{i=0} k\_{i+w} 2^i
//          - \sum\_{i=0}^{w-1} k\_i 2^i + 2^w \\\\
// &= 2^w + 2^w \sum\_{i=0} k\_{i+w} 2^i
// \end{aligned}
// $$
// so instead of computing the subtraction, we can set a carry
// bit, advance \\(w\\) bits, and reindex.
//
// If \\( k \mod 2^w\\) is even, we emit \\(0\\), advance 1 bit
// and reindex.  In fact, by setting all digits to \\(0\\)
// initially, we don't need to emit anything.
public sbyte[] non_adjacent_form(int w)
        {
            // required by the NAF definition
            Debug.Assert(w >= 2);
            // required so that the NAF digits fit in i8
            Debug.Assert(w <= 8);

            //use byteorder::{ ByteOrder, LittleEndian };

            var naf = new sbyte [256];

            var x_u64 = new ulong [5];
            //LittleEndian::read_u64_into(&self.bytes, &mut x_u64[0..4]);

            if (!BitConverter.IsLittleEndian)
            {
                ReadOnlySpan<byte> ub = bytes.ToArray().Reverse().ToArray();

                x_u64[0] = BitConverter.ToUInt64(ub.Slice(0).ToArray(), 0);
                x_u64[1] = BitConverter.ToUInt64(ub.Slice(8).ToArray(), 0);
                x_u64[2] = BitConverter.ToUInt64(ub.Slice(16).ToArray(), 0);
                x_u64[3] = BitConverter.ToUInt64(ub.Slice(24).ToArray(), 0);
            }
            else
            {
                ReadOnlySpan<byte> ub = bytes.Span;

                x_u64[0] = BitConverter.ToUInt64(ub.Slice(0).ToArray(), 0);
                x_u64[1] = BitConverter.ToUInt64(ub.Slice(8).ToArray(), 0);
                x_u64[2] = BitConverter.ToUInt64(ub.Slice(16).ToArray(), 0);
                x_u64[3] = BitConverter.ToUInt64(ub.Slice(24).ToArray(), 0);
            }

            ulong width = (ulong) 1 << w;
            var window_mask = width - 1;

            var pos = 0;
            var carry = 0;
            while (pos < 256)
            {
                // Construct a buffer of bits of the scalar, starting at bit `pos`
                var u64_idx = pos / 64;
                var bit_idx = pos % 64;
                ulong bit_buf;
                if (bit_idx < 64 - w)
                {
                    // This window's bits are contained in a single u64
                    bit_buf = x_u64[u64_idx] >> bit_idx;
                }
                else
                {
                    // Combine the current u64's bits with the bits from the next u64
                    bit_buf = (x_u64[u64_idx] >> bit_idx) | (x_u64[1 + u64_idx] << (64 - bit_idx));
                }

// Add the carry into the current window
                var window = (ulong) carry + (bit_buf & window_mask);

                if ((window & 1) == 0)
                {
                    // If the window value is even, preserve the carry and continue.
                    // Why is the carry preserved?
                    // If carry == 0 and window & 1 == 0, then the next carry should be 0
                    // If carry == 1 and window & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
                    pos += 1;
                    continue;
                }

                if (window < width / 2)
                {
                    carry = 0;
                    naf[pos] = (sbyte) window;
                }
                else
                {
                    carry = 1;
                    naf[pos] = (sbyte) (window - width);
                }

                pos += w;
            }

            return naf;
        }

        ///// Write this scalar in radix 16, with coefficients in \\([-8,8)\\),
        ///// i.e., compute \\(a\_i\\) such that
        ///// $$
        /////    a = a\_0 + a\_1 16\^1 + \cdots + a_{63} 16\^{63},
        ///// $$
        ///// with \\(-8 \leq a_i < 8\\) for \\(0 \leq i < 63\\) and \\(-8 \leq a_{63} \leq 8\\).
        //pub(crate) fn to_radix_16(&self) -> [i8; 64] {
        //    debug_assert!(self[31] <= 127);
        //    let mut output = [0i8; 64];

        //    // Step 1: change radix.
        //    // Convert from radix 256 (bytes) to radix 16 (nibbles)
        //    #[inline(always)]
        //    fn bot_half(x: u8) -> u8 { (x >> 0) & 15 }
        //    #[inline(always)]
        //    fn top_half(x: u8) -> u8 { (x >> 4) & 15 }

        //    for i in 0..32 {
        //        output[2*i  ] = bot_half(self[i]) as i8;
        //        output[2*i+1] = top_half(self[i]) as i8;
        //    }
        //    // Precondition note: since self[31] <= 127, output[63] <= 7

        //    // Step 2: recenter coefficients from [0,16) to [-8,8)
        //    for i in 0..63 {
        //        let carry    = (output[i] + 8) >> 4;
        //        output[i  ] -= carry << 4;
        //        output[i+1] += carry;
        //    }
        //    // Precondition note: output[63] is not recentered.  It
        //    // increases by carry <= 1.  Thus output[63] <= 8.

        //    output
        //}

        // Unpack this `Scalar` to an `UnpackedScalar` for faster arithmetic.
        public UnpackedScalar unpack()
        {
            return UnpackedScalar.from_bytes(bytes.ToArray());
        }

        /// Reduce this `Scalar` modulo \\(\ell\\).
        public Scalar reduce()
        {
            var x = unpack();
            var xR = UnpackedScalar.mul_internal(x.Value, Constant.R.Value);
            var x_mod_l = UnpackedScalar.montgomery_reduce(xR);
            return x_mod_l.pack();
        }

        // Check whether this `Scalar` is the canonical representative mod \\(\ell\\).
        //
        // This is intended for uses like input validation, where variable-time code is acceptable.
        //
        // ```
        // # extern crate curve25519_dalek;
        // # extern crate subtle;
        // # use curve25519_dalek::scalar::Scalar;
        // # use subtle::ConditionallyAssignable;
        // # fn main() {
        // // 2^255 - 1, since `from_bits` clears the high bit
        // let _2_255_minus_1 = Scalar::from_bits([0xff;32]);
        // assert!(!_2_255_minus_1.is_canonical());
        //
        // let reduced = _2_255_minus_1.reduce();
        // assert!(reduced.is_canonical());
        // # }
        // ```
        public bool is_canonical()
        {
            return this == reduce();
        }

        public override bool Equals(object obj)
        {
            var fe = obj as Scalar?;

            if (fe == null)
            {
                return false;
            }

            return bytes.Span.SequenceEqual(fe?.bytes.ToArray());
        }

        public override int GetHashCode()
        {
            return bytes.GetHashCode();
        }

        public static bool operator ==(Scalar x, Scalar y)
        {
            return x.bytes.Span.SequenceEqual(y.bytes.ToArray());
        }

        public static bool operator !=(Scalar x, Scalar y)
        {
            return !x.bytes.Span.SequenceEqual(y.bytes.ToArray());
        }
    }
}