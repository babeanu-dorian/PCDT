#include "he_aes_cmac/cmac_keys_ctxt.h"

#include <iterator>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "he_aes_cmac/public_key.h"

namespace HeAesCmac {

    CmacKeysCtxt CmacKeysCtxt::genKeysCtxt(CryptoPP::RandomNumberGenerator &rng, PublicKey const &hePk) {
        std::vector<CryptoPP::byte> aesKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(aesKey.data(), aesKey.size());
        return genKeysCtxt(aesKey, hePk);
    }

    CmacKeysCtxt CmacKeysCtxt::genKeysCtxt(std::vector<CryptoPP::byte> const &aesKey,
                                           PublicKey const &hePk) {
        std::vector<CryptoPP::byte> key1, key2;
        genSubKeys(aesKey, key1, key2);
        return encryptKeys(aesKey, key1, key2, hePk);
    }

    CmacKeysCtxt CmacKeysCtxt::encryptKeys(std::vector<CryptoPP::byte> const &aesKey,
                                           std::vector<CryptoPP::byte> const &key1,
                                           std::vector<CryptoPP::byte> const &key2,
                                           PublicKey const &hePk) {
        std::vector<helib::Ctxt> aesKeyCtxt;
        helib::Ctxt key1Ctxt(hePk.pk());
        helib::Ctxt key2Ctxt(hePk.pk());
        hePk.encryptAesKey(aesKey, aesKeyCtxt);
        hePk.encryptBlock(key1, key1Ctxt);
        hePk.encryptBlock(key2, key2Ctxt);
        return CmacKeysCtxt(aesKeyCtxt, key1Ctxt, key2Ctxt);
    }

    void CmacKeysCtxt::genSubKeys(std::vector<CryptoPP::byte> const &aesKey,
                                  std::vector<CryptoPP::byte> &key1,
                                  std::vector<CryptoPP::byte> &key2) {
        static CryptoPP::byte const rb = 0x87;
        static CryptoPP::byte const msb = 0x80;
        static std::vector<CryptoPP::byte> const zeroBlock(0, CryptoPP::AES::BLOCKSIZE);

        key1.clear();
        key2.clear();
        key1.reserve(CryptoPP::AES::BLOCKSIZE);
        key2.reserve(CryptoPP::AES::BLOCKSIZE);

        // initialize key1 to AES-128(aesKey, 0) 
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption aes;
        aes.SetKey(aesKey.data(), aesKey.size());
        CryptoPP::StringSource(zeroBlock.data(), zeroBlock.size(), true,
            new CryptoPP::StreamTransformationFilter(aes, new CryptoPP::VectorSink(key1)));

        // set key1
        CryptoPP::byte msbKey1 = key1[0] & msb;
        leftshift(key1);
        if (msbKey1) {
            key1.back() ^= rb;
        }

        // set key2
        key2 = key1;
        leftshift(key2);
        msbKey1 = key1[0] & msb;
        if (msbKey1) {
            key2.back() ^= rb;
        }
    }

    CmacKeysCtxt::CmacKeysCtxt(std::vector<helib::Ctxt> const &aesKey,
                               helib::Ctxt const &key1, helib::Ctxt const &key2):
        _aesKey(aesKey),
        _key1(key1),
        _key2(key2)
    {}

    std::vector<helib::Ctxt> const &CmacKeysCtxt::aesKey() const {
        return _aesKey;
    }

    helib::Ctxt const &CmacKeysCtxt::key1() const {
        return _key1;
    }
    
    helib::Ctxt const &CmacKeysCtxt::key2() const {
        return _key2;
    }

    void CmacKeysCtxt::leftshift(std::vector<CryptoPP::byte> &data) {
        CryptoPP::byte overflow = 0;
        for (auto it = std::begin(data); it != std::end(data); ++it) {
            CryptoPP::byte nextOverflow = (*it & 0x80) ? 1 : 0;
            *it = ((*it) << 1) | overflow;
            overflow = nextOverflow;
        }
    }
    
}