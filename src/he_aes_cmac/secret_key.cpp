#include "he_aes_cmac/secret_key.h"

#include "cryptopp/aes.h"

namespace HeAesCmac {

    SecretKey::SecretKey(helib::SecKey const &sk, HomAES const &heAes):
        _sk(sk),
        _heAes(heAes)
    {}
    
    void SecretKey::decryptBlocks(std::vector<helib::Ctxt> const &input,
                                  std::vector<CryptoPP::byte> &output) const {
        output.clear();
        output.reserve(input.size() * CryptoPP::AES::BLOCKSIZE);
        for (auto it = input.cbegin(); it != input.cend(); ++it) {
            std::vector<CryptoPP::byte> block;
            decryptBlock(*it, block);
            output.insert(output.end(), block.cbegin(), block.cend());
        }
    }

    void SecretKey::decryptBlock(helib::Ctxt const &input,
                                 std::vector<CryptoPP::byte> &output) const {
        NTL::Vec<NTL::ZZX> ptxt(NTL::INIT_SIZE, 1);
        _sk.Decrypt(ptxt[0], input);
        decode4AES(output, ptxt, _heAes.getEA());
        output.resize(CryptoPP::AES::BLOCKSIZE);
    }
}