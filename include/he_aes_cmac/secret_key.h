#ifndef HEAESCMAC_SECRET_KEY_H
#define HEAESCMAC_SECRET_KEY_H

#include <vector>

#include "helib/helib.h"
#include "he_aes_cmac/homAES.h"
#include "cryptopp/config_int.h"

namespace HeAesCmac {

    class SecretKey {
        helib::SecKey const _sk;
        HomAES const _heAes;

        public:
            SecretKey(helib::SecKey const &sk, HomAES const &heAes);
            void decryptBlocks(std::vector<helib::Ctxt> const &input,
                               std::vector<CryptoPP::byte> &output) const;
            void decryptBlock(helib::Ctxt const &input, std::vector<CryptoPP::byte> &output) const;

    };
}

#endif /* !HEAESCMAC_SECRET_KEY_H */