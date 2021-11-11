#ifndef HEAESCMAC_CMAC_KEYS_CTXT_H
#define HEAESCMAC_CMAC_KEYS_CTXT_H

#include "helib/helib.h"
#include "cryptopp/osrng.h"

namespace HeAesCmac {

    class PublicKey;

    class CmacKeysCtxt {

        std::vector<helib::Ctxt> const _aesKey;
        helib::Ctxt const _key1;
        helib::Ctxt const _key2;

        public:
            static CmacKeysCtxt genKeysCtxt(CryptoPP::RandomNumberGenerator &rng, PublicKey const &hePk);
            static CmacKeysCtxt genKeysCtxt(std::vector<CryptoPP::byte> const &aesKey,
                                            PublicKey const &hePk);
            static CmacKeysCtxt encryptKeys(std::vector<CryptoPP::byte> const &aesKey,
                                            std::vector<CryptoPP::byte> const &key1,
                                            std::vector<CryptoPP::byte> const &key2,
                                            PublicKey const &hePk);
            static void genSubKeys(std::vector<CryptoPP::byte> const &aesKey,
                                   std::vector<CryptoPP::byte> &key1,
                                   std::vector<CryptoPP::byte> &key2);

            CmacKeysCtxt(std::vector<helib::Ctxt> const &aesKey,
                         helib::Ctxt const &key1, helib::Ctxt const &key2);

            std::vector<helib::Ctxt> const &aesKey() const;
            helib::Ctxt const &key1() const;
            helib::Ctxt const &key2() const;
        
        private:
            static void leftshift(std::vector<CryptoPP::byte> &data);
    };
}

#endif /* !HEAESCMAC_CMAC_KEYS_CTXT_H */