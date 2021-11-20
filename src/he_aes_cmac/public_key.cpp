#include "he_aes_cmac/public_key.h"
#include "he_aes_cmac/cmac_keys_ctxt.h"

#include <iterator>

namespace HeAesCmac {

    PublicKey::PublicKey(helib::PubKey const &pk, HomAES const &heAes):
        _pk(pk),
        _heAes(heAes)
    {}

    helib::PubKey const &PublicKey::pk() const {
        return _pk;
    }
    
    void PublicKey::encryptBlocks(std::vector<CryptoPP::byte> const &input,
                                  std::vector<helib::Ctxt> &output) const {
        size_t nBlocks = input.size() / CryptoPP::AES::BLOCKSIZE
                        + (input.size() % CryptoPP::AES::BLOCKSIZE != 0);
        output.clear();
        output.resize(nBlocks, helib::Ctxt(_pk));
        for (size_t i = 0; i != nBlocks; ++i) {
            auto blockStartIt(std::next(input.cbegin(), i * CryptoPP::AES::BLOCKSIZE));
            auto blockEndIt(
                std::distance(blockStartIt, input.cend()) > CryptoPP::AES::BLOCKSIZE ?
                std::next(blockStartIt, CryptoPP::AES::BLOCKSIZE) :
                input.cend()
            );
            std::vector<CryptoPP::byte> block(blockStartIt, blockEndIt);
            size_t initialBlockSize = block.size();
            block.resize(CryptoPP::AES::BLOCKSIZE);
            if (initialBlockSize != block.size()) {
                block[initialBlockSize] = 0x80;
            }
            encryptBlock(block, output[i]);
        }
    }

    void PublicKey::encryptBlock(std::vector<CryptoPP::byte> const &input,
                                 helib::Ctxt &output) const {
        NTL::Vec<NTL::ZZX> encodedBytes;
        encode4AES(encodedBytes, input, _heAes.getEA());
        _pk.Encrypt(output, encodedBytes[0]);
    }

    void PublicKey::encryptAesKey(std::vector<CryptoPP::byte> const &key,
                                  std::vector<helib::Ctxt> &output) const {
        std::vector<CryptoPP::byte> aesKey(key);
        _heAes.encryptAESkey(output, aesKey, _pk);
    }

    void PublicKey::heAesCmac(CmacKeysCtxt const &key,
                              std::vector<helib::Ctxt> const &input,
                              helib::Ctxt const &padded,
                              helib::Ctxt &output) const {
        // compute padding key
        helib::Ptxt<helib::BGV> ones(padded.getContext());
        ones.negate();
        helib::Ctxt tmpCtxt(padded);
        tmpCtxt *= key.key1();
        helib::Ctxt padKey(padded);
        padKey += ones;
        padKey *= key.key2();
        padKey += tmpCtxt;

        std::vector<helib::Ctxt> tmp(1, helib::Ctxt(_pk));
        for (auto it = input.cbegin(); it != input.cend(); ++it) {
            tmp[0] += *it;
            if (std::distance(it, input.cend()) == 1) {
                tmp[0] += padKey;
            }
            _heAes.homAESenc(tmp, key.aesKey());
        }
        output = tmp[0];
    }
}