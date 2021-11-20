#include "pcdt/he_int.h"

#include <bitset>

#include <iostream>
#include <chrono>

namespace pcdt {

    void HeInt::aggregate(std::function<HeInt&(HeInt&, HeInt const &)> op, std::vector<HeInt> &vec, HeInt &result) {
        size_t lvl = vec.size();
        while (lvl != 1) {
            bool evenLvl = (bool) (lvl % 2);
            lvl /= 2;
            for (size_t i = 0; i != lvl; ++i) {
                op(vec[i], vec[i + lvl]);
            }
            if (evenLvl) {
                vec[lvl] = vec[2 * lvl];
                ++lvl;
            }
        }
        result = vec[0];
    }

    void HeInt::intToPtxt(int val, size_t nBits, helib::Ptxt<helib::BGV> &ptxt) {
        std::bitset<32> bits(val);
        ptxt[0] = bits[bits.size() - 1];
        for (size_t i = 0; i != nBits; ++i) {
            ptxt[nBits - i - 1] = bits[i];
        }
    }

    void HeInt::mask(size_t start, size_t end, helib::Ptxt<helib::BGV> &ptxt) {
        if (start >= end) {
            return;
        }

        for (; start != end; ++start) {
            ptxt[start] = 1;
        }
    }

    int HeInt::ptxtToInt(helib::Ptxt<helib::BGV> const &ptxt, size_t nBits) {
        int result = 0;
        bool negative = (ptxt[0] == 1);
        for (size_t i = 0; i != nBits; ++i) {
            bool bit = (ptxt[i] == 1) ^ negative;
            result = (result << 1) + bit;
        }
        if (negative) {
            return -(++result);
        } else {
            return result;
        }
    }

    HeInt operator<(HeInt const &lhs, HeInt const &rhs) {
        HeInt result(lhs);
        HeInt dRes(lhs);
        result.negate();
        result &= rhs;
        dRes ^= rhs;
        HeInt temp(dRes);
        result ^= temp.select(0, 1);
        dRes.negate();
        std::vector<HeInt> dVec(lhs.nBits(), dRes);
        for (size_t i = 1; i != lhs.nBits(); ++i) {
            dVec[i].shift(i, true);
        }
        HeInt::aggregate(&HeInt::operator&=, dVec, dRes);
        result &= dRes;
        result.bitAggregate(&HeInt::operator^=);
        return result;
    }

    HeInt::HeInt(int val, helib::SecKey const &sk):
        _ctxt(sk),
        _dim(sk.getContext().ea->dimension() - 1),
        _ones(sk.getContext()),
        _sk(&sk)
    {
        helib::Ptxt<helib::BGV> ptxt(sk.getContext());
        intToPtxt(val, _dim, ptxt);
        const helib::PubKey& pk = sk;
        pk.Encrypt(_ctxt, ptxt);
        mask(0, nBits(), _ones);
    }

    size_t HeInt::nBits() const {
        return _ctxt.getContext().ea->sizeOfDimension(_dim);
    }

    int HeInt::decrypt(helib::SecKey const &sk) const {
        helib::Ptxt<helib::BGV> ptxt(_ctxt.getContext());
        sk.Decrypt(ptxt, _ctxt);
        return ptxtToInt(ptxt, _dim);
    }

    helib::Ctxt const &HeInt::ctxt() const {
        return _ctxt;
    }
    
    
    helib::SecKey const *HeInt::sk() const {
        return _sk;
    }

    HeInt &HeInt::negate() {
        recryptIfNeeded();
        _ctxt += _ones;
        return *this;
    }

    HeInt &HeInt::rotate(int n) {
        recryptIfNeeded();
        _ctxt.getContext().ea->rotate1D(_ctxt, _dim, n);
        return *this;
    }

    HeInt &HeInt::shift(int n, bool bit) {
        recryptIfNeeded();
        _ctxt.getContext().ea->shift1D(_ctxt, _dim, n);
        if (bit) {
            helib::Ptxt<helib::BGV> fill(_ctxt.getContext());
            if (n < 0) {
                size_t bits = nBits();
                mask(bits + n, bits, fill);
            } else {
                mask(0, n, fill);
            }
            _ctxt += fill;
        }
        return *this;
    }

    HeInt &HeInt::select(size_t start, size_t end) {
        recryptIfNeeded();
        helib::Ptxt<helib::BGV> selection(_ctxt.getContext());
        mask(start, end, selection);
        _ctxt *= selection;
        return *this;
    }

    HeInt &HeInt::bitAggregate(std::function<HeInt&(HeInt&, HeInt const &)> op) {
        for (size_t lvl = 1; lvl != nBits(); lvl *= 2) {
            HeInt tmp(*this);
            tmp.rotate(lvl);
            op(*this, tmp);
        }
        return *this;
    }

    HeInt &HeInt::operator^=(HeInt const &rhs) {
        recryptIfNeeded();
        _ctxt += rhs._ctxt;
        return *this;
    }

    HeInt &HeInt::operator&=(HeInt const &rhs) {
        recryptIfNeeded();
        _ctxt *= rhs._ctxt;
        return *this;
    }

    HeInt &HeInt::operator+=(HeInt const &rhs) {
        std::vector<HeInt> s;
        s.reserve(nBits() / 2);
        s.push_back(*this);
        s[0] ^= rhs;
        s.push_back(s[0]);
        s[1].select(1, nBits() - 1).rotate(-1);
        size_t pow = 1;
        for (size_t i = 2; i != nBits() / 2; ++i) {
            if (i == 2 * pow) {
                s.push_back(s[pow]);
                s[i].shift(-pow, false);
                s[i] &= s[pow];
                pow = i;
            } else {
                s.push_back(s[i - pow + 1]);
                s[i].shift(1 - pow, false);
                s[i] &= s[pow - 1];
            }
        }

        std::vector<HeInt> c;
        c.reserve(nBits());
        c.push_back(*this);
        c[0] &= rhs;
        c.push_back(c[0]);
        c[1].shift(-1, false);
        pow = 1;
        for (size_t i = 2; i != nBits(); ++i) {
            if (i == 2 * pow) {
                c.push_back(c[pow]);
                c[i].shift(-pow, false);
                c[i] &= s[pow];
                pow = i;
            } else {
                c.push_back(c[i - pow + 1]);
                c[i].shift(1 - pow, false);
                c[i] &= s[pow - 1];
            }
        }

        c[0] = s[0];
        aggregate(&HeInt::operator^=, c, *this);
        return *this;
    }

    HeInt &HeInt::operator-=(HeInt const &rhs) {
        HeInt tmp(rhs);
        return *this += (tmp.negate() += HeInt(1, *_sk));
    }

    HeInt &HeInt::operator*=(HeInt const &rhs) {
        std::vector<HeInt> tmp(nBits(), rhs);
        for (size_t i = 0; i != nBits(); ++i) {
            size_t mBit = nBits() - i - 1;
            tmp[i].select(mBit, mBit + 1).bitAggregate(&HeInt::operator^=);
            tmp[i] &= *this;
            tmp[i].shift(-i, false);
        }
        aggregate(&HeInt::operator+=, tmp, *this);
        return *this;
    }

    HeInt &HeInt::operator/=(HeInt const &rhs) {
        HeInt r(*this);
        r.select(0, 1);
        r -= rhs;
        HeInt q(r);
        q.negate().select(0, 1);
        for (size_t i = nBits() - 1; i != 0; ++i) {
            HeInt c(r);
            c.select(1, 0).bitAggregate(&HeInt::operator^=);
            HeInt cNeg(c);
            cNeg.negate();
            HeInt y(rhs);
            y.negate();
            y += HeInt(1, *_sk);
            y &= cNeg;
            c &= rhs;
            y ^= c;
            r.shift(-1, false);
            HeInt rUpdate(*this);
            rUpdate.select(nBits() - i, nBits() - i + 1).rotate(i - 1);
            r ^= rUpdate;
            r += y;
            HeInt qUpdate(r);
            qUpdate.negate().select(0, 1).rotate(nBits() - i);
            q ^= qUpdate;
        }
        _ctxt = q._ctxt;
        return *this;
    }

    void HeInt::recryptIfNeeded() {
        std::cout << "Bit cpacity: " << _ctxt.bitCapacity() << std::endl;
        if (_ctxt.bitCapacity() < BIT_CAPACITY_MIN) {
            auto start = std::chrono::steady_clock::now();
            _ctxt.getPubKey().thinReCrypt(_ctxt);
            std::cout << "Recryption time (ms): "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
                      << std::endl;
        }

    }
}