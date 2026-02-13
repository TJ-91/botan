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
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>
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
      DataSource_Memory src(key_bits);
      BER_Decoder(src).decode(raw_key, ASN1_Type::OctetString).verify_end();
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
         /*
         The code requires sizeof(size_t) >= ceil(tree_height / 8)

         Maximum supported tree height is 20, ceil(20/8) == 3, so 4 byte
         size_t is sufficient for all defined parameters, or even a
         (hypothetical) tree height 32, which would be extremely slow to
         compute.
         */
         static_assert(sizeof(size_t) >= 4, "size_t is big enough to support leaf index");

         const secure_vector<uint8_t> raw_key = extract_raw_private_key(key_bits, xmssmt_params);

         if(raw_key.size() != m_xmssmt_params.raw_private_key_size()) {
            throw Decoding_Error("Invalid XMSS^MT private key size");
         }

         BufferSlicer s(raw_key);

         // We're not interested in the public key here
         s.skip(m_xmssmt_params.raw_public_key_size());

         auto unused_leaf_bytes = s.take(xmssmt_params.encoded_idx_size());
         uint64_t unused_leaf = 0;
         for(size_t i = 0; i < unused_leaf_bytes.size(); i++) {
            unused_leaf = (unused_leaf << 8) | static_cast<uint64_t>(unused_leaf_bytes[i]);
         }
         if(unused_leaf >= (1ULL << m_xmssmt_params.tree_height())) {
            throw Decoding_Error("XMSS private key leaf index out of bounds");
         }

         m_prf = s.copy_as_secure_vector(m_xmssmt_params.element_size());
         m_private_seed = s.copy_as_secure_vector(m_xmssmt_params.element_size());
         set_unused_leaf_index(unused_leaf);

         BOTAN_ASSERT_NOMSG(s.empty());
      }

      secure_vector<uint8_t> serialize(std::vector<uint8_t> raw_public_key) const {
         std::vector<uint8_t> unused_index(m_xmssmt_params.encoded_idx_size());
         // store_be(static_cast<uint64_t>(unused_leaf_index()), unused_index.data());
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

      std::shared_ptr<Atomic<size_t>> recover_global_leaf_index() const {
         BOTAN_ASSERT(
            m_private_seed.size() == m_xmssmt_params.element_size() && m_prf.size() == m_xmssmt_params.element_size(),
            "Trying to retrieve index for partially initialized key");
         return m_index_reg.get(m_private_seed, m_prf);
      }

      void set_unused_leaf_index(size_t idx) {
         if(idx >= (1ULL << m_xmssmt_params.tree_height())) {
            throw Decoding_Error("XMSS private key leaf index out of bounds");
         } else {
            std::atomic<size_t>& index = static_cast<std::atomic<size_t>&>(*recover_global_leaf_index());
            size_t current = 0;

            // NOLINTNEXTLINE(*-avoid-do-while)
            do {
               current = index.load();
               if(current > idx) {
                  return;
               }
            } while(!index.compare_exchange_strong(current, idx));
         }
      }

      size_t reserve_unused_leaf_index() {
         const size_t idx = (static_cast<std::atomic<size_t>&>(*recover_global_leaf_index())).fetch_add(1);
         if(idx >= m_xmssmt_params.total_number_of_signatures()) {
            throw Decoding_Error("XMSS private key, one time signatures exhausted");
         }
         return idx;
      }

      size_t unused_leaf_index() const { return *recover_global_leaf_index(); }  // TODO MAKE 64!

      size_t remaining_signatures() const {
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
   adrs.set_layer_addr(m_xmssmt_params.tree_layers() - 1);
   m_root = tree_hash(0, XMSSMT_PublicKey::m_xmssmt_params.xmss_tree_height(), adrs);
}

XMSSMT_PrivateKey::XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                                     size_t idx_leaf,
                                     secure_vector<uint8_t> wots_priv_seed,
                                     secure_vector<uint8_t> prf,
                                     secure_vector<uint8_t> root,
                                     secure_vector<uint8_t> public_seed) :
      XMSSMT_PublicKey(xmssmt_algo_id, std::move(root), std::move(public_seed)),
      m_private(std::make_shared<XMSSMT_PrivateKey_Internal>(
         m_xmssmt_params, m_wots_params, std::move(wots_priv_seed), std::move(prf))) {
   m_private->set_unused_leaf_index(idx_leaf);
   BOTAN_ARG_CHECK(m_private->prf_value().size() == m_xmssmt_params.element_size(),
                   "XMSS: unexpected byte length of PRF value");
   BOTAN_ARG_CHECK(m_private->private_seed().size() == m_xmssmt_params.element_size(),
                   "XMSS: unexpected byte length of private seed");
}

secure_vector<uint8_t> XMSSMT_PrivateKey::tree_hash(size_t start_idx,
                                                    size_t target_node_height,
                                                    const XMSS_Address& adrs) {
   BOTAN_ASSERT_NOMSG(target_node_height <= 30);
   BOTAN_ASSERT((start_idx % (static_cast<size_t>(1) << target_node_height)) == 0,
                "Start index must be divisible by 2^{target node height}.");

#if defined(BOTAN_HAS_THREAD_UTILS)
   // determine number of parallel tasks to split the tree_hashing into.

   Thread_Pool& thread_pool = Thread_Pool::global_instance();

   const size_t split_level = std::min(target_node_height, thread_pool.worker_count());

   // skip parallelization overhead for leaf nodes.
   if(split_level == 0) {
      secure_vector<uint8_t> result;
      tree_hash_subtree(result, start_idx, target_node_height, adrs);
      return result;
   }

   const size_t subtrees = static_cast<size_t>(1) << split_level;
   const size_t last_idx = (static_cast<size_t>(1) << (target_node_height)) + start_idx;
   const size_t offs = (last_idx - start_idx) / subtrees;
   // this cast cannot overflow because target_node_height is limited
   uint8_t level = static_cast<uint8_t>(split_level);  // current level in the tree

   BOTAN_ASSERT((last_idx - start_idx) % subtrees == 0,
                "Number of worker threads in tree_hash need to divide range "
                "of calculated nodes.");

   std::vector<secure_vector<uint8_t>> nodes(subtrees,
                                             secure_vector<uint8_t>(XMSSMT_PublicKey::m_xmssmt_params.element_size()));
   std::vector<XMSS_Address> node_addresses(subtrees, adrs);
   std::vector<XMSS_Hash> xmss_hash(subtrees, m_private->hash());
   std::vector<std::future<XMSS_Address>> work_treehash;
   std::vector<std::future<void>> work_randthash;

   // Calculate multiple subtrees in parallel.
   for(size_t i = 0; i < subtrees; i++) {
      node_addresses[i].set_type(XMSS_Address::Type::Hash_Tree_Address);

      using tree_hash_subtree_fn_t =
         XMSS_Address (XMSSMT_PrivateKey::*)(secure_vector<uint8_t>&, size_t, size_t, const XMSS_Address&, XMSS_Hash&);

      const tree_hash_subtree_fn_t work_fn = &XMSSMT_PrivateKey::tree_hash_subtree;

      work_treehash.push_back(thread_pool.run(work_fn,
                                              this,
                                              std::ref(nodes[i]),
                                              start_idx + i * offs,
                                              target_node_height - split_level,
                                              std::cref(node_addresses[i]),
                                              std::ref(xmss_hash[i])));
   }

   // for(auto& w : work) {
   //    w.get();
   // }
   for(size_t i = 0; i < work_treehash.size(); i++) {
      XMSS_Address node_adrs = work_treehash[i].get();
      node_addresses[i].set_tree_height(node_adrs.get_tree_height());
      node_addresses[i].set_tree_index(node_adrs.get_tree_index());
   }
   work_treehash.clear();

   // Parallelize the top tree levels horizontally
   while(level-- > 1) {
      std::vector<secure_vector<uint8_t>> ro_nodes(nodes.begin(),
                                                   nodes.begin() + (static_cast<size_t>(1) << (level + 1)));

      for(size_t i = 0; i < (static_cast<size_t>(1) << level); i++) {
         BOTAN_ASSERT_NOMSG(xmss_hash.size() > i);

         node_addresses[i].set_tree_height(static_cast<uint32_t>(target_node_height - (level + 1)));
         node_addresses[i].set_tree_index((node_addresses[2 * i + 1].get_tree_index() - 1) >> 1);

         work_randthash.push_back(thread_pool.run(&XMSS_Core_Ops::randomize_tree_hash,
                                                  std::ref(nodes[i]),
                                                  std::cref(ro_nodes[2 * i]),
                                                  std::cref(ro_nodes[2 * i + 1]),
                                                  std::ref(node_addresses[i]),
                                                  std::cref(this->public_seed()),
                                                  std::ref(xmss_hash[i]),
                                                  m_xmssmt_params.element_size()));
      }

      for(auto& w : work_randthash) {
         w.get();
      }
      work_randthash.clear();
   }

   // Avoid creation an extra thread to calculate root node.
   node_addresses[0].set_tree_height(static_cast<uint32_t>(target_node_height - 1));
   node_addresses[0].set_tree_index((node_addresses[1].get_tree_index() - 1) >> 1);
   XMSS_Core_Ops::randomize_tree_hash(nodes[0],
                                      nodes[0],
                                      nodes[1],
                                      node_addresses[0],
                                      this->public_seed(),
                                      m_private->hash(),
                                      m_xmssmt_params.element_size());
   return nodes[0];
#else
   secure_vector<uint8_t> result;
   tree_hash_subtree(result, start_idx, target_node_height, adrs, m_private->hash());
   return result;
#endif
}

void XMSSMT_PrivateKey::tree_hash_subtree(secure_vector<uint8_t>& result,
                                          size_t start_idx,
                                          size_t target_node_height,
                                          const XMSS_Address& adrs) {
   (void)tree_hash_subtree(result, start_idx, target_node_height, adrs, m_private->hash());
}

XMSS_Address XMSSMT_PrivateKey::tree_hash_subtree(secure_vector<uint8_t>& result,
                                                  size_t start_idx,
                                                  size_t target_node_height,
                                                  const XMSS_Address& adrs,
                                                  XMSS_Hash& hash) {
   const secure_vector<uint8_t>& seed = this->public_seed();

   std::vector<secure_vector<uint8_t>> nodes(target_node_height + 1,
                                             secure_vector<uint8_t>(XMSSMT_PublicKey::m_xmssmt_params.element_size()));

   // node stack, holds all nodes on stack and one extra "pending" node. This
   // temporary node referred to as "node" in the XMSS standard document stays
   // a pending element, meaning it is not regarded as element on the stack
   // until level is increased.
   std::vector<uint8_t> node_levels(target_node_height + 1);

   uint8_t level = 0;  // current level on the node stack.
   const size_t last_idx = (static_cast<size_t>(1) << target_node_height) + start_idx;

   // we need copies of the address
   XMSS_Address l_tree_adrs(adrs);
   XMSS_Address ots_adrs(adrs);
   XMSS_Address node_adrs(adrs);

   // ... and only care about the layer/tree address so it's ok to reset the rest via set_type
   l_tree_adrs.set_type(XMSS_Address::Type::LTree_Address);
   ots_adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
   node_adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);

   for(size_t i = start_idx; i < last_idx; i++) {
      ots_adrs.set_ots_address(static_cast<uint32_t>(i));
      ots_adrs.set_hash_address(0);
      const XMSS_WOTS_PublicKey pk = this->wots_public_key_for(ots_adrs, hash);

      l_tree_adrs.set_ltree_address(static_cast<uint32_t>(i));
      XMSS_Core_Ops::create_l_tree(
         nodes[level], pk.key_data(), l_tree_adrs, seed, hash, m_xmssmt_params.element_size(), m_xmssmt_params.len());
      node_levels[level] = 0;

      node_adrs.set_tree_height(0);
      node_adrs.set_tree_index(static_cast<uint32_t>(i));

      while(level > 0 && node_levels[level] == node_levels[level - 1]) {
         node_adrs.set_tree_index(((node_adrs.get_tree_index() - 1) >> 1));
         XMSS_Core_Ops::randomize_tree_hash(
            nodes[level - 1], nodes[level - 1], nodes[level], node_adrs, seed, hash, m_xmssmt_params.element_size());
         node_levels[level - 1]++;
         level--;  //Pop stack top element
         node_adrs.set_tree_height(node_adrs.get_tree_height() + 1);
      }
      level++;  //push temporary node to stack
   }
   result = nodes[level - 1];

   return node_adrs;
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

size_t XMSSMT_PrivateKey::reserve_unused_leaf_index() {
   return m_private->reserve_unused_leaf_index();
}

size_t XMSSMT_PrivateKey::unused_leaf_index() const {
   return m_private->unused_leaf_index();
}

size_t XMSSMT_PrivateKey::remaining_signatures() const {
   return m_private->remaining_signatures();
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
