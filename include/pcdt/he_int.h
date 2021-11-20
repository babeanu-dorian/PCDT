#ifndef HE_INT_H
#define HE_INT_H

#include <vector>
#include <cstdint>
#include <functional>

#include "helib/helib.h"

namespace pcdt {

    class HeInt {

        static int const BIT_CAPACITY_MIN = 40;

        helib::Ctxt _ctxt;
        size_t _dim;
        helib::Ptxt<helib::BGV> _ones;

        helib::SecKey const *_sk; // hack to simulate bootstrapping

        public:
            // this will not preserve the input vector
            static void aggregate(std::function<HeInt&(HeInt&, HeInt const &)> op, std::vector<HeInt> &vec, HeInt &result);

            static void intToPtxt(int val, size_t nBits, helib::Ptxt<helib::BGV> &ptxt);

            // output ptxt for value 0^start||1^(end - start)||0^(bits - end)
            // assumes ptxt is 0-filled
            static void mask(size_t start, size_t end, helib::Ptxt<helib::BGV> &ptxt);

            static int ptxtToInt(helib::Ptxt<helib::BGV> const &ptxt, size_t nBits);

            friend HeInt operator<(HeInt const &lhs, HeInt const &rhs);

            HeInt(int val, helib::SecKey const &sk); // replace SecKey with PubKey if bootstrapping works

            size_t nBits() const;
            int decrypt(helib::SecKey const &sk) const;
            helib::Ctxt const &ctxt() const;
            helib::SecKey const *sk() const;

            HeInt &negate();
            HeInt &rotate(int n);
            HeInt &shift(int n, bool bit);
            HeInt &select(size_t start, size_t end);
            HeInt &bitAggregate(std::function<HeInt&(HeInt&, HeInt const &)> op);

            // homomorphic addition (bitwise XOR over binary)
            HeInt &operator^=(HeInt const &rhs);

            // homomorphic multiplication (bitwise AND over binary)
            HeInt &operator&=(HeInt const &rhs);

            HeInt &operator+=(HeInt const &rhs);
            HeInt &operator-=(HeInt const &rhs);
            HeInt &operator*=(HeInt const &rhs);
            HeInt &operator/=(HeInt const &rhs);

            void recryptIfNeeded();
    };

    
    HeInt operator<(HeInt const &lhs, HeInt const &rhs);

}

#endif /* !HE_INT_H */