﻿using System.Runtime.CompilerServices;


namespace Diffused.Crypto.Curve
{
    public partial struct UnpackedScalar
    {

    /// Pack the limbs of this `UnpackedScalar` into a `Scalar`.
    public Scalar pack()
    {
        return new Scalar {bytes = to_bytes()};
    }

    ///// Inverts an UnpackedScalar in Montgomery form.
    //pub fn montgomery_invert(&self) -> UnpackedScalar {
    //    // Uses the addition chain from
    //    // https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
    //    let    _1 = self;
    //    let   _10 = _1.montgomery_square();
    //    let  _100 = _10.montgomery_square();
    //    let   _11 = UnpackedScalar::montgomery_mul(&_10,     &_1);
    //    let  _101 = UnpackedScalar::montgomery_mul(&_10,    &_11);
    //    let  _111 = UnpackedScalar::montgomery_mul(&_10,   &_101);
    //    let _1001 = UnpackedScalar::montgomery_mul(&_10,   &_111);
    //    let _1011 = UnpackedScalar::montgomery_mul(&_10,  &_1001);
    //    let _1111 = UnpackedScalar::montgomery_mul(&_100, &_1011);

    //    // _10000
    //    let mut y = UnpackedScalar::montgomery_mul(&_1111, &_1);

    //    #[inline]
    //    fn square_multiply(y: &mut UnpackedScalar, squarings: usize, x: &UnpackedScalar) {
    //        for _ in 0..squarings {
    //            *y = y.montgomery_square();
    //        }
    //        *y = UnpackedScalar::montgomery_mul(y, x);
    //    }

    //    square_multiply(&mut y, 123 + 3, &_101);
    //    square_multiply(&mut y,   2 + 2, &_11);
    //    square_multiply(&mut y,   1 + 4, &_1111);
    //    square_multiply(&mut y,   1 + 4, &_1111);
    //    square_multiply(&mut y,       4, &_1001);
    //    square_multiply(&mut y,       2, &_11);
    //    square_multiply(&mut y,   1 + 4, &_1111);
    //    square_multiply(&mut y,   1 + 3, &_101);
    //    square_multiply(&mut y,   3 + 3, &_101);
    //    square_multiply(&mut y,       3, &_111);
    //    square_multiply(&mut y,   1 + 4, &_1111);
    //    square_multiply(&mut y,   2 + 3, &_111);
    //    square_multiply(&mut y,   2 + 2, &_11);
    //    square_multiply(&mut y,   1 + 4, &_1011);
    //    square_multiply(&mut y,   2 + 4, &_1011);
    //    square_multiply(&mut y,   6 + 4, &_1001);
    //    square_multiply(&mut y,   2 + 2, &_11);
    //    square_multiply(&mut y,   3 + 2, &_11);
    //    square_multiply(&mut y,   3 + 2, &_11);
    //    square_multiply(&mut y,   1 + 4, &_1001);
    //    square_multiply(&mut y,   1 + 3, &_111);
    //    square_multiply(&mut y,   2 + 4, &_1111);
    //    square_multiply(&mut y,   1 + 4, &_1011);
    //    square_multiply(&mut y,       3, &_101);
    //    square_multiply(&mut y,   2 + 4, &_1111);
    //    square_multiply(&mut y,       3, &_101);
    //    square_multiply(&mut y,   1 + 2, &_11);

    //    y
    //}

    ///// Inverts an UnpackedScalar not in Montgomery form.
    //pub fn invert(&self) -> UnpackedScalar {
    //    self.to_montgomery().montgomery_invert().from_montgomery()
    //}


    }
}
