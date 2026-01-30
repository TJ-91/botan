/*
 * XMSS Core
 * Some core algorithms of XMSS that are shared across operations and with XMSS^MT
 * (C) 2016,2017 Matthias Gierlings
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/internal/xmss_core.h>

#include <botan/internal/xmss_hash.h>
#include <botan/internal/xmss_wots.h>

namespace Botan {

void XMSS_Core_Ops::randomize_tree_hash(secure_vector<uint8_t>& result,
                                        const secure_vector<uint8_t>& left,
                                        const secure_vector<uint8_t>& right,
                                        XMSS_Address& adrs,
                                        const secure_vector<uint8_t>& seed,
                                        XMSS_Hash& hash,
                                        size_t xmss_element_size) {
   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Key_Mode);
   secure_vector<uint8_t> key;
   hash.prf(key, seed, adrs.bytes());

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_MSB_Mode);
   secure_vector<uint8_t> bitmask_l;
   hash.prf(bitmask_l, seed, adrs.bytes());

   adrs.set_key_mask_mode(XMSS_Address::Key_Mask::Mask_LSB_Mode);
   secure_vector<uint8_t> bitmask_r;
   hash.prf(bitmask_r, seed, adrs.bytes());

   BOTAN_ASSERT(bitmask_l.size() == left.size() && bitmask_r.size() == right.size(),
                "Bitmask size doesn't match node size.");

   secure_vector<uint8_t> concat_xor(xmss_element_size * 2);
   for(size_t i = 0; i < left.size(); i++) {
      concat_xor[i] = left[i] ^ bitmask_l[i];
      concat_xor[i + left.size()] = right[i] ^ bitmask_r[i];
   }

   hash.h(result, key, concat_xor);
}

void XMSS_Core_Ops::create_l_tree(secure_vector<uint8_t>& result,
                                  wots_keysig_t pk,
                                  XMSS_Address& adrs,
                                  const secure_vector<uint8_t>& seed,
                                  XMSS_Hash& hash,
                                  size_t xmss_element_size,
                                  size_t xmss_wots_len) {
   size_t l = xmss_wots_len;
   adrs.set_tree_height(0);

   while(l > 1) {
      for(size_t i = 0; i < l >> 1; i++) {
         adrs.set_tree_index(static_cast<uint32_t>(i));
         randomize_tree_hash(pk[i], pk[2 * i], pk[2 * i + 1], adrs, seed, hash, xmss_element_size);
      }
      if((l & 0x01) == 0x01) {
         pk[l >> 1] = pk[l - 1];
      }
      l = (l >> 1) + (l & 0x01);
      adrs.set_tree_height(adrs.get_tree_height() + 1);
   }
   result = pk[0];
}

secure_vector<uint8_t> XMSS_Core_Ops::root_from_signature(uint64_t idx_leaf,
                                                          const XMSS_TreeSignature& tree_sig,
                                                          const secure_vector<uint8_t>& msg,
                                                          XMSS_Address& adrs,
                                                          const secure_vector<uint8_t>& seed,
                                                          XMSS_Hash& hash,
                                                          size_t xmss_element_size,
                                                          size_t xmss_tree_height,
                                                          size_t xmss_wots_len,
                                                          XMSS_WOTS_Parameters::ots_algorithm_t ots_oid) {
   adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
   adrs.set_ots_address(idx_leaf);

   const XMSS_WOTS_Parameters wots_params(ots_oid);
   const XMSS_WOTS_PublicKey pub_key_ots(wots_params, seed, tree_sig.ots_signature, msg, adrs, hash);

   adrs.set_type(XMSS_Address::Type::LTree_Address);
   adrs.set_ltree_address(idx_leaf);

   std::array<secure_vector<uint8_t>, 2> node;
   XMSS_Core_Ops::create_l_tree(node[0], pub_key_ots.key_data(), adrs, seed, hash, xmss_element_size, xmss_wots_len);

   adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
   adrs.set_tree_index(idx_leaf);

   for(size_t k = 0; k < xmss_tree_height; k++) {
      adrs.set_tree_height(static_cast<uint32_t>(k));
      if(((idx_leaf / (static_cast<size_t>(1) << k)) & 0x01) == 0) {
         adrs.set_tree_index(adrs.get_tree_index() >> 1);
         XMSS_Core_Ops::randomize_tree_hash(
            node[1], node[0], tree_sig.authentication_path[k], adrs, seed, hash, xmss_element_size);
      } else {
         adrs.set_tree_index((adrs.get_tree_index() - 1) >> 1);
         XMSS_Core_Ops::randomize_tree_hash(
            node[1], tree_sig.authentication_path[k], node[0], adrs, seed, hash, xmss_element_size);
      }
      node[0] = node[1];
   }

   return node[0];
}

}  // namespace Botan
