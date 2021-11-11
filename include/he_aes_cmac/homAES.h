// Original version from https://github.com/homenc/HElib/tree/master/misc/aes
// is no longer compatible with current helib,
// fix copied from https://github.com/homenc/HElib/pull/343

/** homAES.h - homomorphic AES using HElib
 */

#ifndef HOM_AES_H
#define HOM_AES_H

#include <stdint.h>
#include "NTL/ZZX.h"
#include "NTL/GF2X.h"
#include "helib/EncryptedArray.h"
#include "helib/hypercube.h"

#ifdef USE_ZZX_POLY
#define PolyType NTL::ZZX
#else
#if (ALT_CRT)
#define PolyType helib::AltCRT
#else
#define PolyType helib::DoubleCRT
#endif
#endif

class HomAES {
  const helib::EncryptedArrayDerived<helib::PA_GF2> ea2;

  std::vector<PolyType> encAffMat, decAffMat; // The GF2 affine map constants
  PolyType affVec;

  std::vector<PolyType> encLinTran, decLinTran; // The rowShift/colMix constants

  NTL::GF2X XinSlots; // "Fully packed" poly with X in all the slots, for packing
  NTL::Mat<NTL::GF2X> unpacking; // constants for unpacking after recryption

  void batchRecrypt(std::vector<helib::Ctxt>& data) const; // recryption during AES computation

public:
  static const NTL::GF2X aesPoly;  // The AES polynomial: X^8+X^4+X^3+X+1

  //! Constructor. If context is bootstrappable then also
  //! the packing/unpacking constants are computed.
  explicit HomAES(const helib::Context& context);

  //! Method for copmuting packing/unpacking constants after initialization
  void setPackingConstants();

  //! run the AES key-expansion and then encrypt the expanded key
  void encryptAESkey(std::vector<helib::Ctxt>& eKey, std::vector<uint8_t>& aesKey,
		     const helib::PubKey& hePK) const;

  //! Perform AES encryption/decryption on "raw bytes" (ECB mode)
  //! The input bytes are either plaintext or AES-encrypted ciphertext
  void homAESenc(std::vector<helib::Ctxt>& eData, const std::vector<helib::Ctxt>& eKey,
		 const std::vector<uint8_t> inBytes) const;
  void homAESdec(std::vector<helib::Ctxt>& eData, const std::vector<helib::Ctxt>& eKey,
		 const std::vector<uint8_t> inBytes) const;

  //! In-place AES encryption/decryption on HE encrypted bytes (ECB mode)
  void homAESenc(std::vector<helib::Ctxt>& eData, const std::vector<helib::Ctxt>& eKey) const;
  void homAESdec(std::vector<helib::Ctxt>& eData, const std::vector<helib::Ctxt>& eKey) const;

  // utility functions
  const helib::EncryptedArrayDerived<helib::PA_GF2>& getEA() const { return ea2; }
};


// Encode/decode AES plaintext/ciphertext bytes as native HE plaintext
void encode4AES(NTL::Vec<NTL::ZZX>& encData, const std::vector<uint8_t>& data,
		const helib::EncryptedArrayDerived<helib::PA_GF2>& ea2);
void decode4AES(std::vector<uint8_t>& data, const NTL::Vec<NTL::ZZX>& encData,
		const helib::EncryptedArrayDerived<helib::PA_GF2>& ea2);

#endif /* !HOM_AES_H */