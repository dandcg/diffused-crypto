namespace Diffused.Crypto.Architecture.x64
{
    public interface IFieldElement
    {
        ulong[] Value { get; }
        void AddAssign(IFieldElement rhs);
        void Add(IFieldElement rhs);
        void SubAssign(IFieldElement rhs);
        void Sub(IFieldElement rhs);
        void MulAssign(IFieldElement rhs);
        void Mul(IFieldElement rhs);

        /// Invert the sign of this field element
        void negate();

        /// Construct zero.
        void zero();

        /// Construct one.
        void one();

        /// Construct -1.
        void minus_one();

        void from_bytes(byte[] bytes);

        /// Serialize this `FieldElement64` to a 32-byte array.  The
        /// encoding is canonical.
        byte[] to_bytes();

        /// Returns the square of this field element.
        IFieldElement square();
    }
}