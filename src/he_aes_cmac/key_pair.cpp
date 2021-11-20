#include "he_aes_cmac/key_pair.h"

namespace HeAesCmac {

    helib::Context KeyPair::genContext(SecurityParams const &params) {
        helib::Context context(params.m, 2, params.r, params.gens, params.ords);
        context.zMStar.set_cM(params.cm);
        buildModChain(context, params.k, params.c);
        //context.makeBootstrappable(helib::convert<NTL::Vec<long>, std::vector<long>>(params.mvec));
        return context;
    }

    KeyPair KeyPair::genKeyPair(helib::Context const &context, unsigned long hw) {
        // Set up HomAES object
        HomAES homAes(context);

        // Generate BGV secret key.
        helib::SecKey sk(context);
        sk.GenSecKey(hw);
        genKeySwitchingMatrices(sk, context.zMStar.getM());
        helib::addFrbMatrices(sk);
        helib::addSome1DMatrices(sk);
        //sk.genRecryptData();

        // pk implicitly extracted from sk
        return KeyPair(PublicKey(sk, homAes), SecretKey(sk, homAes));
    }

    KeyPair::KeyPair(PublicKey const &pk, SecretKey const &sk):
        _pk(pk),
        _sk(sk)
    {}

    PublicKey const &KeyPair::pk() const {
        return _pk;
    }

    SecretKey const &KeyPair::sk() const {
        return _sk;
    }

    void KeyPair::genKeySwitchingMatrices(helib::SecKey &sk, unsigned long m) {
        long ord = sk.getContext().zMStar.OrderOf(0);
        // rotation along 1st dim by size i * ord / 16
        for (long i = 1; i != CryptoPP::AES::BLOCKSIZE; ++i) {
            long exp = i * ord / CryptoPP::AES::BLOCKSIZE;
            long val = NTL::PowerMod(sk.getContext().zMStar.ZmStarGen(0), exp, m); // val = g^exp
            // From s(X^val) to s(X)
            sk.GenKeySWmatrix(1, val);
            if (!sk.getContext().zMStar.SameOrd(0))
            // also from s(X^{1/val}) to s(X)
            sk.GenKeySWmatrix(1, NTL::InvMod(val,m));
        }
    }
}