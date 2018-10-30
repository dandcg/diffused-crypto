using System;
using System.Runtime.CompilerServices;
using Diffused.Crypto.Types;

[assembly: InternalsVisibleTo("Diffused.Crypto.Tests")] 
// ReSharper disable once CheckNamespace
namespace Diffused.Crypto.Curve
{
    //! Arithmetic mod \\(2\^{252} + 27742317777372353535851937790883648493\\)
    //! with five \\(52\\)-bit unsigned limbs.
    //!
    //! \\(51\\)-bit limbs would cover the desired bit range (\\(253\\)
    //! bits), but isn't large enough to reduce a \\(512\\)-bit number with
    //! Montgomery multiplication, so \\(52\\) bits is used instead.  To see
    //! that this is safe for intermediate results, note that the largest
    //! limb in a \\(5\times 5\\) product of \\(52\\)-bit limbs will be
    //!
    //! ```text
    //! (0xfffffffffffff^2) * 5 = 0x4ffffffffffff60000000000005 (107 bits).
    //! ```

    public partial struct UnpackedScalar
    {
        private readonly Memory<ulong> value;

        internal Span<ulong> Value => value.Span; 

        public override string ToString()
        {
            return $"Scalar64: {string.Join(", ", value.ToArray())}";
        }

        public UnpackedScalar(ulong[] inp)
        {
            value = inp;
        }

        /// u64 * u64 = u128 multiply helper
        private static UInt128 m(ulong x, ulong y)
        {
            return (UInt128) x * (UInt128) y;
        }


  public static UnpackedScalar zero()
  {
      return new UnpackedScalar(new ulong[] {0, 0, 0, 0, 0});
  }

    /// Unpack a 32 byte / 256 bit scalar into 5 52-bit limbs.
    public static UnpackedScalar from_bytes(byte[] bytes)
    {
        var words = new ulong[4];
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                words[i] |= ((ulong)bytes[(i * 8) + j]) << (j * 8);
            }
        }

        var mask = (((ulong)1) << 52) - 1;
        var top_mask = (((ulong)1) << 48) - 1;
        var s = UnpackedScalar.zero();
          var ss=s.value.Span;

        ss[0] =   words[0]                            & mask;
        ss[ 1] = ((words[0] >> 52) | (words[1] << 12)) & mask;
        ss[ 2] = ((words[1] >> 40) | (words[2] << 24)) & mask;
        ss[ 3] = ((words[2] >> 28) | (words[3] << 36)) & mask;
        ss[ 4] =  (words[3] >> 16)                     & top_mask;

        return s;
    }

    /// Reduce a 64 byte / 512 bit scalar mod l
    public static UnpackedScalar from_bytes_wide(byte[] bytes) 
    {
        var words = new ulong[8];
        for (int i = 0; i < 8; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                words[i] |= ((ulong)bytes[(i * 8) + j]) << (j * 8);
            }
        }



        var mask = (((ulong)1) << 52) - 1;
        var lo = UnpackedScalar.zero();
        var hi = UnpackedScalar.zero();

        var los=lo.value.Span;
        var his=hi.value.Span;


        los[0] =   words[ 0]                             & mask;
        los[1] = ((words[ 0] >> 52) | (words[ 1] << 12)) & mask;
        los[2] = ((words[ 1] >> 40) | (words[ 2] << 24)) & mask;
        los[3] = ((words[ 2] >> 28) | (words[ 3] << 36)) & mask;
        los[4] = ((words[ 3] >> 16) | (words[ 4] << 48)) & mask;
        his[0] =  (words[ 4] >>  4)                      & mask;
        his[1] = ((words[ 4] >> 56) | (words[ 5] <<  8)) & mask;
        his[2] = ((words[ 5] >> 44) | (words[ 6] << 20)) & mask;
        his[3] = ((words[ 6] >> 32) | (words[ 7] << 32)) & mask;
        his[4] =   words[ 7] >> 20                             ;

        lo = UnpackedScalar.montgomery_mul(lo, Constant.R);  // (lo * R) / R = lo
        hi = UnpackedScalar.montgomery_mul(hi, Constant.RR); // (hi * R^2) / R = hi * R

        return UnpackedScalar.add(hi, lo);
    }

    /// Pack the limbs of this `Scalar64` into 32 bytes
    public byte[] to_bytes() 
    {
        var s = new byte[32];

        var vs = value.Span;

        s[0]  =  (byte)(vs[ 0] >>  0)             ;
        s[1]  =  (byte)(vs[ 0] >>  8)                    ;
        s[2]  =  (byte)(vs[ 0] >> 16)                    ;
        s[3]  = (byte) (vs[ 0] >> 24)                    ;
        s[4]  = (byte) (vs[ 0] >> 32)                    ;
        s[5]  =(byte)  (vs[ 0] >> 40)                    ;
        s[6]  =(byte) ((vs[ 0] >> 48) | (vs[ 1] << 4)) ;
        s[7]  = (byte) (vs[ 1] >>  4)                    ;
        s[8]  = (byte) (vs[ 1] >> 12)                    ;
        s[9]  = (byte) (vs[ 1] >> 20)                    ;
        s[10] = (byte) (vs[ 1] >> 28)                    ;
        s[11] = (byte) (vs[ 1] >> 36)                    ;
        s[12] = (byte) (vs[ 1] >> 44)                    ;
        s[13] = (byte) (vs[ 2] >>  0)                    ;
        s[14] = (byte) (vs[ 2] >>  8)                    ;
        s[15] =(byte)  (vs[ 2] >> 16)                    ;
        s[16] = (byte) (vs[ 2] >> 24)                    ;
        s[17] = (byte) (vs[ 2] >> 32)                    ;
        s[18] = (byte) (vs[ 2] >> 40)                    ;
        s[19] = (byte)((vs[ 2] >> 48) | (vs[ 3] << 4)) ;
        s[20] = (byte) (vs[ 3] >>  4)                    ;
        s[21] = (byte) (vs[ 3] >> 12)                    ;
        s[22] = (byte) (vs[ 3] >> 20)                    ;
        s[23] = (byte) (vs[ 3] >> 28)                    ;
        s[24] =(byte)  (vs[ 3] >> 36)                    ;
        s[25] = (byte) (vs[ 3] >> 44)                    ;
        s[26] = (byte) (vs[ 4] >>  0)                    ;
        s[27] =(byte)  (vs[ 4] >>  8)                    ;
        s[28] = (byte) (vs[ 4] >> 16)                    ;
        s[29] =(byte)  (vs[ 4] >> 24)                    ;
        s[30] = (byte) (vs[ 4] >> 32)                    ;
        s[31] = (byte) (vs[ 4] >> 40)                    ;

        return s;
    }

    /// Compute `a + b` (mod l)
    public static UnpackedScalar add(UnpackedScalar a, UnpackedScalar b) 
    {
       var sum = UnpackedScalar.zero();
        var sums = sum.value.Span;
      var mask = ((ulong)1 << 52) - 1;

        var asp = a.value.Span;
        var bsp = b.value.Span;

        // a + b
     ulong carry = 0;
        for (int i = 0; i < 5; i++)
        {
            carry = asp[i] + bsp[i] + (carry >> 52);
            sums[i] = carry & mask;
        }


        // subtract l if the sum is >= l
        return UnpackedScalar.sub(sum, Constant.L);
    }

    /// Compute `a - b` (mod l)
    public static UnpackedScalar sub(UnpackedScalar a, UnpackedScalar b) 
    {
        var difference = UnpackedScalar.zero();
        var differencesp = difference.value.Span;
        var mask = ((ulong)1 << 52) - 1;


        var asp = a.value.Span;
        var bsp = b.value.Span;

        // a - b
       ulong borrow = 0;

        for (int i = 0; i < 5; i++)
        {
            borrow = asp[i]-(bsp[i] + (borrow >> 63));
            differencesp[i] = borrow & mask;
        }


        // conditionally add l if the difference is negative
       var underflow_mask = ((borrow >> 63) ^ 1)-(1);
       ulong  carry = 0;

            for (int i = 0; i < 5; i++)
            {
                carry = (carry >> 52) + differencesp[i] + (Constant.L.value.Span[i] & underflow_mask);
                differencesp[i] = carry & mask;
            }
            
        return difference;
    }

    /// Compute `a * b`
    internal static UInt128[] mul_internal(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b)
    {
        var z = new UInt128[9];

        z[0] = m(a[0],b[0]);
        z[1] = m(a[0],b[1]) + m(a[1],b[0]);
        z[2] = m(a[0],b[2]) + m(a[1],b[1]) + m(a[2],b[0]);
        z[3] = m(a[0],b[3]) + m(a[1],b[2]) + m(a[2],b[1]) + m(a[3],b[0]);
        z[4] = m(a[0],b[4]) + m(a[1],b[3]) + m(a[2],b[2]) + m(a[3],b[1]) + m(a[4],b[0]);
        z[5] =                m(a[1],b[4]) + m(a[2],b[3]) + m(a[3],b[2]) + m(a[4],b[1]);
        z[6] =                               m(a[2],b[4]) + m(a[3],b[3]) + m(a[4],b[2]);
        z[7] =                                              m(a[3],b[4]) + m(a[4],b[3]);
        z[8] =                                                             m(a[4],b[4]);

        return z;
    }

    /// Compute `a^2`
    public static UInt128[] square_internal(ReadOnlySpan<ulong> a) 
    {
        var aa = new ulong[]{
            a[0]*2,
            a[1]*2,
            a[2]*2,
            a[3]*2,
        };


        return new UInt128[]
        {
            m(a[0], a[0]),
            m(aa[0], a[1]),
            m(aa[0], a[2]) + m(a[1], a[1]),
            m(aa[0], a[3]) + m(aa[1], a[2]),
            m(aa[0], a[4]) + m(aa[1], a[3]) + m(a[2], a[2]),
            m(aa[1], a[4]) + m(aa[2], a[3]),
            m(aa[2], a[4]) + m(a[3], a[3]),
            m(aa[3], a[4]),
            m(a[4], a[4])
        };

    }

    /// Compute `limbs/R` (mod l), where R is the Montgomery modulus 2^260

    public static UnpackedScalar montgomery_reduce(UInt128[] limbs)  
    {
   

        (UInt128,ulong) part1(UInt128 sum) 
        {
            var p = ((ulong)sum)*(Constant.LFACTOR) & (((ulong)1 << 52) - 1);
            return ((sum + m(p, Constant.L.value.Span[0])) >> 52, p);
        }

    
        (UInt128,ulong) part2(UInt128 sum) 
        {
            var w = ((ulong)sum ) & (((ulong)1 << 52) - 1);
            return (sum >> 52, w);
        }

        // note: l3 is zero, so its multiplies can be skipped
        var l = Constant.L;
        var ls = l.value.Span;

        // the first half computes the Montgomery adjustment factor n, and begins adding n*l to make limbs divisible by R
        UInt128 carry;
        ulong n0;
        (carry, n0) = part1(        limbs[0]);
        ulong n1;
        (carry, n1) = part1(carry + limbs[1] + m(n0,ls[1]));
        ulong n2;
        (carry, n2) = part1(carry + limbs[2] + m(n0,ls[2]) + m(n1,ls[1]));
        ulong n3;
        (carry, n3) = part1(carry + limbs[3]              + m(n1,ls[2]) + m(n2,ls[1]));
        ulong n4;
        (carry, n4) = part1(carry + limbs[4] + m(n0,ls[4])              + m(n2,ls[2]) + m(n3,ls[1]));

        // limbs is divisible by R now, so we can divide by R by simply storing the upper half as the result
        ulong r0;
        (carry, r0) = part2(carry + limbs[5]              + m(n1,ls[4])              + m(n3,ls[2]) + m(n4,ls[1]));
        ulong r1;
        (carry, r1) = part2(carry + limbs[6]                           + m(n2,ls[4])              + m(n4,ls[2]));
        ulong r2;
        (carry, r2) = part2(carry + limbs[7]                                        + m(n3,ls[4])             );
        ulong r3;
        (carry, r3) = part2(carry + limbs[8]                                                     + m(n4,ls[4]));
        var          r4 = (ulong)carry;

        // result may be >= l, so attempt to subtract l
        return UnpackedScalar.sub(new UnpackedScalar(new ulong[] {r0, r1, r2, r3, r4}), l);
    }

    /// Compute `a * b` (mod l)

    public static UnpackedScalar mul(UnpackedScalar a, UnpackedScalar b) 
    {
        var ab = UnpackedScalar.montgomery_reduce(UnpackedScalar.mul_internal(a.value.Span, b.value.Span));
        return UnpackedScalar.montgomery_reduce(UnpackedScalar.mul_internal(ab.value.Span, Constant.RR.value.Span));
    }

    /// Compute `a^2` (mod l)
    // XXX we don't expose square() via the Scalar API
    public  UnpackedScalar square() 
    {
       var aa = UnpackedScalar.montgomery_reduce(UnpackedScalar.square_internal(value.Span));
        return UnpackedScalar.montgomery_reduce(UnpackedScalar.mul_internal(aa.value.Span, Constant.RR.value.Span));
    }

    /// Compute `(a * b) / R` (mod l), where R is the Montgomery modulus 2^260

    public static UnpackedScalar montgomery_mul(UnpackedScalar a, UnpackedScalar b)
    {
        return UnpackedScalar.montgomery_reduce(UnpackedScalar.mul_internal(a.value.Span, b.value.Span));
    }

    /// Compute `(a^2) / R` (mod l) in Montgomery form, where R is the Montgomery modulus 2^260
 
    public UnpackedScalar montgomery_square()
    {
        return UnpackedScalar.montgomery_reduce(UnpackedScalar.square_internal(value.Span));
    }

    /// Puts a Scalar64 in to Montgomery form, i.e. computes `a*R (mod l)`

    public  UnpackedScalar to_montgomery()
    {
        return UnpackedScalar.montgomery_mul(this, Constant.RR);
    }

    /// Takes a Scalar64 out of Montgomery form, i.e. computes `a/R (mod l)`

    public UnpackedScalar from_montgomery()
    {
        var limbs =new UInt128[9];
        for (int i = 0; i < 5; i++)
        {
            limbs[i] = value.Span[i] ;      
 }

        return UnpackedScalar.montgomery_reduce(limbs);
    }



    }
}
