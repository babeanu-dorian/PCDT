#ifndef HEAESCMAC_KEY_PAIR_H
#define HEAESCMAC_KEY_PAIR_H

#include "he_aes_cmac/public_key.h"
#include "he_aes_cmac/secret_key.h"
#include "he_aes_cmac/security_params.h"

namespace HeAesCmac {

    class KeyPair {
        PublicKey const _pk;
        SecretKey const _sk;

        public:
            static helib::Context genContext(SecurityParams const &params);
            static KeyPair genKeyPair(helib::Context const &context, unsigned long hw);

            KeyPair(PublicKey const &pk, SecretKey const &sk);

            PublicKey const &pk() const;
            SecretKey const &sk() const;
        
        private:
            static void genKeySwitchingMatrices(helib::SecKey &sk, unsigned long m);
    };
}

#endif /* !HEAESCMAC_KEY_PAIR_H */