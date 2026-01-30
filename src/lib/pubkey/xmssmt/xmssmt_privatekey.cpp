/*
 * XMSS^MT Private Key
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmssmt.h>

namespace Botan {

XMSSMT_PrivateKey::XMSSMT_PrivateKey(std::span<const uint8_t> key_bits) :
      XMSSMT_PublicKey(key_bits)
// m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(m_xmss_params, m_wots_params, key_bits))
{}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id, RandomNumberGenerator& rng) :
      XMSSMT_PublicKey(xmssmt_algo_id, rng) {}

// m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(m_xmss_params, m_wots_params, wots_derivation_method, rng)) {
// XMSS_Address adrs;
// m_root = tree_hash(0, XMSS_PublicKey::m_xmss_params.tree_height(), adrs);

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                                     size_t idx_leaf,
                                     secure_vector<uint8_t> wots_priv_seed,
                                     secure_vector<uint8_t> prf,
                                     secure_vector<uint8_t> root,
                                     secure_vector<uint8_t> public_seed) :
      XMSSMT_PublicKey(xmssmt_algo_id, std::move(root), std::move(public_seed)) {
   (void)idx_leaf;
   (void)wots_priv_seed;
   (void)prf;
}

//    m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(
//       m_xmss_params, m_wots_params, wots_derivation_method, std::move(wots_priv_seed), std::move(prf))) {
// m_private->set_unused_leaf_index(idx_leaf);
// BOTAN_ARG_CHECK(m_private->prf_value().size() == m_xmss_params.element_size(),
//                 "XMSS: unexpected byte length of PRF value");
// BOTAN_ARG_CHECK(m_private->private_seed().size() == m_xmss_params.element_size(),
//                 "XMSS: unexpected byte length of private seed");

secure_vector<uint8_t> XMSSMT_PrivateKey::private_key_bits() const {
   // return DER_Encoder().encode(raw_private_key(), ASN1_Type::OctetString).get_contents();
   return {};
}

size_t XMSSMT_PrivateKey::unused_leaf_index() const {
   // return m_private->unused_leaf_index();
   return 1;
}

size_t XMSSMT_PrivateKey::remaining_signatures() const {
   // return m_private->remaining_signatures();
   return 1;
}

std::optional<uint64_t> XMSSMT_PrivateKey::remaining_operations() const {
   // return m_private->remaining_signatures();
   return 1;
}

secure_vector<uint8_t> XMSSMT_PrivateKey::raw_private_key() const {
   // return m_private->serialize(raw_public_key());
   return {};
}

std::unique_ptr<Public_Key> XMSSMT_PrivateKey::public_key() const {
   return std::make_unique<XMSSMT_PublicKey>(xmssmt_parameters().oid(), root(), public_seed());
}

}  // namespace Botan
