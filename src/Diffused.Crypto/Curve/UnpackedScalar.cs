namespace Diffused.Crypto.Curve
{
    public partial struct UnpackedScalar
    {
        /// Pack the limbs of this `UnpackedScalar` into a `Scalar`.
        public Scalar pack()
        {
            return new Scalar(to_bytes());
        }

        /// Inverts an UnpackedScalar in Montgomery form.
        public UnpackedScalar montgomery_invert()
        {
            // Uses the addition chain from
            // https://briansmith.org/ecc-inversion-addition-chains-01#curve25519_scalar_inversion
            var _1 = this;
            var _10 = _1.montgomery_square();
            var _100 = _10.montgomery_square();
            var _11 = montgomery_mul(_10, _1);
            var _101 = montgomery_mul(_10, _11);
            var _111 = montgomery_mul(_10, _101);
            var _1001 = montgomery_mul(_10, _111);
            var _1011 = montgomery_mul(_10, _1001);
            var _1111 = montgomery_mul(_100, _1011);

            // _10000
            var y = montgomery_mul(_1111, _1);

            void square_multiply(ref UnpackedScalar iy, uint squarings, UnpackedScalar x)
            {
                for (int i = 0; i < squarings; i++)
                {
                    iy = iy.montgomery_square();
                }

                y = montgomery_mul(iy, x);
            }

            square_multiply(ref y, 123 + 3, _101);
            square_multiply(ref y, 2 + 2, _11);
            square_multiply(ref y, 1 + 4, _1111);
            square_multiply(ref y, 1 + 4, _1111);
            square_multiply(ref y, 4, _1001);
            square_multiply(ref y, 2, _11);
            square_multiply(ref y, 1 + 4, _1111);
            square_multiply(ref y, 1 + 3, _101);
            square_multiply(ref y, 3 + 3, _101);
            square_multiply(ref y, 3, _111);
            square_multiply(ref y, 1 + 4, _1111);
            square_multiply(ref y, 2 + 3, _111);
            square_multiply(ref y, 2 + 2, _11);
            square_multiply(ref y, 1 + 4, _1011);
            square_multiply(ref y, 2 + 4, _1011);
            square_multiply(ref y, 6 + 4, _1001);
            square_multiply(ref y, 2 + 2, _11);
            square_multiply(ref y, 3 + 2, _11);
            square_multiply(ref y, 3 + 2, _11);
            square_multiply(ref y, 1 + 4, _1001);
            square_multiply(ref y, 1 + 3, _111);
            square_multiply(ref y, 2 + 4, _1111);
            square_multiply(ref y, 1 + 4, _1011);
            square_multiply(ref y, 3, _101);
            square_multiply(ref y, 2 + 4, _1111);
            square_multiply(ref y, 3, _101);
            square_multiply(ref y, 1 + 2, _11);

            return y;
        }

        ///// Inverts an UnpackedScalar not in Montgomery form.
        public UnpackedScalar invert()
        {
            return to_montgomery().montgomery_invert().from_montgomery();
        }
    }
}