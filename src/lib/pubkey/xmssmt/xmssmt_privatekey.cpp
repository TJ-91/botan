/*
 * XMSS^MT Private Key
 * (C) 2026 Johannes Roth
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/xmssmt.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/rng.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/xmss_core.h>
#include <botan/internal/xmss_index_registry.h>
#include <botan/internal/xmssmt_signature_operation.h>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif
namespace Botan {

namespace {

// fall back to raw decoding for previous versions, which did not encode an OCTET STRING
secure_vector<uint8_t> extract_raw_private_key(std::span<const uint8_t> key_bits,
                                               const XMSSMT_Parameters& xmssmt_params) {
   secure_vector<uint8_t> raw_key;

   // The public part of the input key bits was already parsed, so we can
   // decide depending on the buffer length whether this must be BER decoded.
   if(key_bits.size() == xmssmt_params.raw_private_key_size()) {
      raw_key.assign(key_bits.begin(), key_bits.end());
   } else {
      BER_Decoder(key_bits).decode(raw_key, ASN1_Type::OctetString).verify_end();
   }

   return raw_key;
}

}  // namespace

class XMSSMT_PrivateKey_Internal {
   public:
      XMSSMT_PrivateKey_Internal(const XMSSMT_Parameters& xmssmt_params,
                                 const XMSS_WOTS_Parameters& wots_params,
                                 RandomNumberGenerator& rng) :
            m_xmssmt_params(xmssmt_params),
            m_wots_params(wots_params),
            m_hash(m_xmssmt_params.hash_function_name(), m_xmssmt_params.hash_id_size()),
            m_prf(rng.random_vec(xmssmt_params.element_size())),
            m_private_seed(rng.random_vec(xmssmt_params.element_size())),
            m_index_reg(XMSS_Index_Registry::get_instance()) {}

      XMSSMT_PrivateKey_Internal(const XMSSMT_Parameters& xmssmt_params,
                                 const XMSS_WOTS_Parameters& wots_params,
                                 secure_vector<uint8_t> private_seed,
                                 secure_vector<uint8_t> prf) :
            m_xmssmt_params(xmssmt_params),
            m_wots_params(wots_params),
            m_hash(m_xmssmt_params.hash_function_name(), m_xmssmt_params.hash_id_size()),
            m_prf(std::move(prf)),
            m_private_seed(std::move(private_seed)),
            m_index_reg(XMSS_Index_Registry::get_instance()) {}

      XMSSMT_PrivateKey_Internal(const XMSSMT_Parameters& xmssmt_params,
                                 const XMSS_WOTS_Parameters& wots_params,
                                 std::span<const uint8_t> key_bits) :
            m_xmssmt_params(xmssmt_params),
            m_wots_params(wots_params),
            m_hash(m_xmssmt_params.hash_function_name(), m_xmssmt_params.hash_id_size()),
            m_index_reg(XMSS_Index_Registry::get_instance()) {
         const secure_vector<uint8_t> raw_key = extract_raw_private_key(key_bits, xmssmt_params);

         if(raw_key.size() != m_xmssmt_params.raw_private_key_size()) {
            throw Decoding_Error("Invalid XMSS^MT private key size");
         }

         BufferSlicer s(raw_key);

         // We're not interested in the public key here
         s.skip(m_xmssmt_params.raw_public_key_size());

         auto unused_leaf_bytes = s.take(xmssmt_params.encoded_idx_size());
         uint64_t unused_leaf = 0;
         for(const uint8_t unused_leaf_byte : unused_leaf_bytes) {
            unused_leaf = (unused_leaf << 8) | static_cast<uint64_t>(unused_leaf_byte);
         }
         if(unused_leaf >= (1ULL << m_xmssmt_params.tree_height())) {
            throw Decoding_Error("XMSS^MT private key leaf index out of bounds");
         }

         m_prf = s.copy_as_secure_vector(m_xmssmt_params.element_size());
         m_private_seed = s.copy_as_secure_vector(m_xmssmt_params.element_size());
         set_unused_leaf_index(unused_leaf);

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      secure_vector<uint8_t> serialize(std::vector<uint8_t> raw_public_key) const {
         std::vector<uint8_t> unused_index(m_xmssmt_params.encoded_idx_size());
         uint64_t idx = unused_leaf_index();
         for(size_t i = 0; i < unused_index.size(); i++) {
            unused_index[unused_index.size() - 1 - i] = static_cast<uint8_t>(idx & 0xFF);
            idx >>= 8;
         }

         return concat<secure_vector<uint8_t>>(raw_public_key, unused_index, m_prf, m_private_seed);
      }

      XMSS_Hash& hash() { return m_hash; }

      const secure_vector<uint8_t>& prf_value() const { return m_prf; }

      const secure_vector<uint8_t>& private_seed() { return m_private_seed; }

      const XMSS_WOTS_Parameters& wots_parameters() { return m_wots_params; }

      XMSS_Index_Registry& index_registry() { return m_index_reg; }

      std::shared_ptr<Atomic<uint64_t>> recover_global_leaf_index() const {
         BOTAN_ASSERT(
            m_private_seed.size() == m_xmssmt_params.element_size() && m_prf.size() == m_xmssmt_params.element_size(),
            "Trying to retrieve index for partially initialized key");
         return m_index_reg.get(m_private_seed, m_prf);
      }

      void set_unused_leaf_index(uint64_t idx) {
         if(idx >= (1ULL << m_xmssmt_params.tree_height())) {
            throw Decoding_Error("XMSS^MT private key leaf index out of bounds");
         } else {
            std::atomic<uint64_t>& index = static_cast<std::atomic<uint64_t>&>(*recover_global_leaf_index());
            uint64_t current = 0;

            // NOLINTNEXTLINE(*-avoid-do-while)
            do {
               current = index.load();
               if(current > idx) {
                  return;
               }
            } while(!index.compare_exchange_strong(current, idx));
         }
      }

      uint64_t reserve_unused_leaf_index() {
         const uint64_t idx = (static_cast<std::atomic<uint64_t>&>(*recover_global_leaf_index())).fetch_add(1);
         if(idx >= m_xmssmt_params.total_number_of_signatures()) {
            throw Decoding_Error("XMSS^MT private key, one time signatures exhausted");
         }
         return idx;
      }

      uint64_t unused_leaf_index() const { return *recover_global_leaf_index(); }

      uint64_t remaining_signatures() const {
         return m_xmssmt_params.total_number_of_signatures() - *recover_global_leaf_index();
      }

   private:
      XMSSMT_Parameters m_xmssmt_params;
      XMSS_WOTS_Parameters m_wots_params;

      XMSS_Hash m_hash;
      secure_vector<uint8_t> m_prf;
      secure_vector<uint8_t> m_private_seed;
      XMSS_Index_Registry& m_index_reg;
};

XMSSMT_PrivateKey::XMSSMT_PrivateKey(std::span<const uint8_t> key_bits) :
      XMSSMT_PublicKey(key_bits),
      m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(m_xmssmt_params, m_wots_params, key_bits)) {}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id, RandomNumberGenerator& rng) :
      XMSSMT_PublicKey(xmssmt_algo_id, rng),
      m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(m_xmssmt_params, m_wots_params, rng)) {
   XMSS_Address adrs;
   adrs.set_layer_addr(static_cast<uint32_t>(m_xmssmt_params.tree_layers() - 1));
   m_root = tree_hash(0, XMSSMT_PublicKey::m_xmssmt_params.xmss_tree_height(), adrs);
}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                                     uint64_t idx_leaf,
                                     secure_vector<uint8_t> wots_priv_seed,
                                     secure_vector<uint8_t> prf,
                                     secure_vector<uint8_t> root,
                                     secure_vector<uint8_t> public_seed) :
      XMSSMT_PublicKey(xmssmt_algo_id, std::move(root), std::move(public_seed)),
      m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(
         m_xmssmt_params, m_wots_params, std::move(wots_priv_seed), std::move(prf))) {
   m_private->set_unused_leaf_index(idx_leaf);
   BOTAN_ARG_CHECK(m_private->prf_value().size() == m_xmssmt_params.element_size(),
                   "XMSS^MT: unexpected byte length of PRF value");
   BOTAN_ARG_CHECK(m_private->private_seed().size() == m_xmssmt_params.element_size(),
                   "XMSS^MT: unexpected byte length of private seed");
}

secure_vector<uint8_t> XMSSMT_PrivateKey::tree_hash(uint32_t start_idx,
                                                    size_t target_node_height,
                                                    const XMSS_Address& adrs) {
   return XMSS_Core_Ops::tree_hash(
      start_idx,
      target_node_height,
      adrs,
      m_private->hash(),
      m_private->wots_parameters(),
      this->public_seed(),
      [this](XMSS_Address& adrs_inner, XMSS_Hash& hash_inner) { return wots_public_key_for(adrs_inner, hash_inner); });
}

XMSS_WOTS_PublicKey XMSSMT_PrivateKey::wots_public_key_for(XMSS_Address& adrs, XMSS_Hash& hash) const {
   const auto private_key = wots_private_key_for(adrs, hash);
   return XMSS_WOTS_PublicKey(m_private->wots_parameters(), m_public_seed, private_key, adrs, hash);
}

XMSS_WOTS_PrivateKey XMSSMT_PrivateKey::wots_private_key_for(XMSS_Address& adrs, XMSS_Hash& hash) const {
   return XMSS_WOTS_PrivateKey(m_private->wots_parameters(), m_public_seed, m_private->private_seed(), adrs, hash);
}

secure_vector<uint8_t> XMSSMT_PrivateKey::private_key_bits() const {
   return DER_Encoder().encode(raw_private_key(), ASN1_Type::OctetString).get_contents();
}

uint64_t XMSSMT_PrivateKey::reserve_unused_leaf_index() {
   return m_private->reserve_unused_leaf_index();
}

std::optional<uint64_t> XMSSMT_PrivateKey::remaining_operations() const {
   return m_private->remaining_signatures();
}

const secure_vector<uint8_t>& XMSSMT_PrivateKey::prf_value() const {
   return m_private->prf_value();
}

secure_vector<uint8_t> XMSSMT_PrivateKey::raw_private_key() const {
   return m_private->serialize(raw_public_key_bits());
}

std::unique_ptr<Public_Key> XMSSMT_PrivateKey::public_key() const {
   return std::make_unique<XMSSMT_PublicKey>(xmssmt_parameters().oid(), root(), public_seed());
}

std::unique_ptr<PK_Ops::Signature> XMSSMT_PrivateKey::create_signature_op(RandomNumberGenerator& /*rng*/,
                                                                          std::string_view /*params*/,
                                                                          std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<XMSSMT_Signature_Operation>(*this);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
