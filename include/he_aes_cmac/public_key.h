#ifndef HEAESCMAC_PUBLIC_KEY_H
#define HEAESCMAC_PUBLIC_KEY_H

#include <cstdint>
#include <vector>

#include "helib/helib.h"
#include "cryptopp/aes.h"
#include "he_aes_cmac/homAES.h"

namespace HeAesCmac {

    class CmacKeysCtxt;

    class PublicKey {

        helib::PubKey const _pk;
        HomAES const _heAes;

        public:
            PublicKey(helib::PubKey const &pk, HomAES const &heAes);
            helib::PubKey const &pk() const;
            HomAES const &heAes() const { // TODO: remove this
                return _heAes;
            }
            void encryptBlocks(std::vector<CryptoPP::byte> const &input,
                               std::vector<helib::Ctxt> &output) const;
            void encryptBlock(std::vector<CryptoPP::byte> const &input,
                              helib::Ctxt &output) const;
            void encryptAesKey(std::vector<CryptoPP::byte> const &key,
                               std::vector<helib::Ctxt> &output) const;
            void heAesCmac(CmacKeysCtxt const &key,
                           std::vector<helib::Ctxt> const &input,
                           bool padded,
                           helib::Ctxt &output) const;
            
    };
}

#endif /* !HEAESCMAC_PUBLIC_KEY_H */