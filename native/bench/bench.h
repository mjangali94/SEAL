// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"
#endif
#include "benchmark/benchmark.h"
#if (SEAL_COMPILER == SEAL_COMPILER_GCC)
#pragma GCC diagnostic pop
#elif (SEAL_COMPILER == SEAL_COMPILER_CLANG)
#pragma clang diagnostic pop
#endif

#include "seal/seal.h"
#include "seal/util/rlwe.h"

namespace sealbench
{
    /**
    Class BMEnv contains a set of required precomputed/preconstructed objects to setup a benchmark case.
    A global BMEnv object is only initialized when a benchmark case for a EncryptionParameters is requested.
    Since benchmark cases for the same parameters are registered together, this avoids heavy precomputation.
    */
    class BMEnv
    {
    public:
        BMEnv() = delete;

        // Allow insecure parameters for experimental purposes.
        // DO NOT USE THIS AS AN EXAMPLE.
        BMEnv(const seal::EncryptionParameters &parms)
        : parms_(parms), context_(parms_, true, seal::sec_level_type::none)
        {
            keygen_ = std::make_shared<seal::KeyGenerator>(context_);
            sk_ = keygen_->secret_key();
            keygen_->create_public_key(pk_);
            if (context_.using_keyswitching())
            {
                keygen_->create_relin_keys(rlk_);
                galois_elts_all_ = context_.key_context_data()->galois_tool()->get_elts_from_steps({ 1 });
                galois_elts_all_.emplace_back(2 * static_cast<uint32_t>(parms_.poly_modulus_degree()) - 1);
                // galois_elts_all_ = context_.key_context_data()->galois_tool()->get_elts_all();
                keygen_->create_galois_keys(galois_elts_all_, glk_);
            }

            encryptor_ = std::make_shared<seal::Encryptor>(context_, pk_, sk_);
            decryptor_ = std::make_shared<seal::Decryptor>(context_, sk_);
            if (parms_.scheme() == seal::scheme_type::bfv || parms_.scheme() == seal::scheme_type::bgv)
            {
                batch_encoder_ = std::make_shared<seal::BatchEncoder>(context_);
            }
            else if (parms_.scheme() == seal::scheme_type::ckks)
            {
                ckks_encoder_ = std::make_shared<seal::CKKSEncoder>(context_);
            }
            evaluator_ = std::make_shared<seal::Evaluator>(context_);

            pt_.resize(std::size_t(2));
            for (std::size_t i = 0; i < 2; i++)
            {
                pt_[i].resize(parms_.poly_modulus_degree());
            }

            ct_.resize(std::size_t(3));
            for (std::size_t i = 0; i < 3; i++)
            {
                ct_[i].resize(context_, std::size_t(2));
            }
        }

        /**
        Getter methods.
        */
        SEAL_NODISCARD const seal::EncryptionParameters &parms() const
        {
            return parms_;
        }

        SEAL_NODISCARD const seal::SEALContext &context() const
        {
            return context_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::KeyGenerator> keygen()
        {
            return keygen_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Encryptor> encryptor()
        {
            return encryptor_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Decryptor> decryptor()
        {
            return decryptor_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::BatchEncoder> batch_encoder()
        {
            return batch_encoder_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::CKKSEncoder> ckks_encoder()
        {
            return ckks_encoder_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Evaluator> evaluator()
        {
            return evaluator_;
        }

        SEAL_NODISCARD seal::SecretKey &sk()
        {
            return sk_;
        }

        SEAL_NODISCARD const seal::SecretKey &sk() const
        {
            return sk_;
        }

        SEAL_NODISCARD seal::PublicKey &pk()
        {
            return pk_;
        }

        SEAL_NODISCARD const seal::PublicKey &pk() const
        {
            return pk_;
        }

        SEAL_NODISCARD seal::RelinKeys &rlk()
        {
            return rlk_;
        }

        SEAL_NODISCARD const seal::RelinKeys &rlk() const
        {
            return rlk_;
        }

        SEAL_NODISCARD seal::GaloisKeys &glk()
        {
            return glk_;
        }

        SEAL_NODISCARD const seal::GaloisKeys &glk() const
        {
            return glk_;
        }

        SEAL_NODISCARD const std::vector<std::uint32_t> &galois_elts_all() const
        {
            return galois_elts_all_;
        }

        SEAL_NODISCARD std::vector<std::uint64_t> &msg_uint64()
        {
            return msg_uint64_;
        }

        SEAL_NODISCARD std::vector<double> &msg_double()
        {
            return msg_double_;
        }

        SEAL_NODISCARD std::vector<seal::Plaintext> &pt()
        {
            return pt_;
        }

        SEAL_NODISCARD std::vector<seal::Ciphertext> &ct()
        {
            return ct_;
        }

        /**
        In most cases, the scale is chosen half as large as the second last prime (or the last if there is only one).
        This avoids "scale out of bound" error in ciphertext/plaintext multiplications.
        */
        SEAL_NODISCARD double safe_scale()
        {
            return pow(2.0, (context_.first_context_data()->parms().coeff_modulus().end() - 1)->bit_count() / 2 - 1);
        }

        /**
        Fill a buffer with a number of random values that are uniformly samples from 0 ~ modulus - 1.
        */
        void randomize_array_mod(std::uint64_t *data, std::size_t count, const seal::Modulus &modulus)
        {
            // For the purpose of benchmark, avoid using seal::UniformRandomGenerator, as it degrades
            // performance with HEXL on some systems, due to AVX512 transitions.
            // See https://travisdowns.github.io/blog/2020/01/17/avxfreq1.html#voltage-only-transitions.
            // This method is not used for random number generation in Microsoft SEAL.
            std::random_device rd;
            std::mt19937_64 generator(rd());
            std::uniform_int_distribution<std::uint64_t> dist(0, modulus.value() - 1);
            std::generate(data, data + count, [&]() { return dist(generator); });
        }

        /**
        Sample an RNS polynomial from uniform distribution.
        */
        void randomize_poly_rns(std::uint64_t *data, const seal::EncryptionParameters &parms)
        {
            std::size_t coeff_count = parms.poly_modulus_degree();
            std::vector<seal::Modulus> coeff_modulus = parms.coeff_modulus();
            for (auto &i : coeff_modulus)
            {
                randomize_array_mod(data, coeff_count, i);
                data += coeff_count;
            }
        }

        /**
        Create a uniform random ciphertext in BFV using the highest-level parameters.
        */
        void randomize_ct_bfv(seal::Ciphertext &ct)
        {
            if (ct.parms_id() != context_.first_parms_id())
            {
                ct.resize(context_, std::size_t(2));
            }
            auto &parms = context_.first_context_data()->parms();
            for (std::size_t i = 0; i < ct.size(); i++)
            {
                randomize_poly_rns(ct.data(i), parms);
            }
            ct.is_ntt_form() = false;
        }

        /**
        Create a uniform random ciphertext in BGV using the highest-level parameters.
        */
        void randomize_ct_bgv(seal::Ciphertext &ct)
        {
            randomize_ct_bfv(ct);
        }

        /**
        Create a uniform random ciphertext in CKKS using the highest-level parameters.
        */
        void randomize_ct_ckks(seal::Ciphertext &ct)
        {
            if (ct.parms_id() != context_.first_parms_id())
            {
                ct.resize(context_, std::size_t(2));
            }
            auto &parms = context_.first_context_data()->parms();
            for (std::size_t i = 0; i < ct.size(); i++)
            {
                randomize_poly_rns(ct.data(i), parms);
            }
            ct.is_ntt_form() = true;
        }

        /**
        Create a uniform random plaintext (single modulus) in BFV.
        */
        void randomize_pt_bfv(seal::Plaintext &pt)
        {
            pt.resize(parms_.poly_modulus_degree());
            pt.parms_id() = seal::parms_id_zero;
            randomize_array_mod(pt.data(), parms_.poly_modulus_degree(), parms_.plain_modulus());
        }

        /**
        Create a uniform random plaintext (single modulus) in BGV.
        */
        void randomize_pt_bgv(seal::Plaintext &pt)
        {
            randomize_pt_bfv(pt);
        }

        /**
        Create a uniform random plaintext (RNS poly) in CKKS.
        */
        void randomize_pt_ckks(seal::Plaintext &pt)
        {
            auto &parms = context_.first_context_data()->parms();
            if (pt.coeff_count() != parms.poly_modulus_degree() * parms.coeff_modulus().size())
            {
                pt.parms_id() = seal::parms_id_zero;
                pt.resize(parms.poly_modulus_degree() * parms.coeff_modulus().size());
            }
            if (pt.parms_id() != context_.first_parms_id())
            {
                pt.parms_id() = context_.first_parms_id();
            }
            randomize_poly_rns(pt.data(), parms);
        }

        /**
        Create a vector of slot_count uniform random integers modulo plain_modululs.
        */
        void randomize_message_uint64(std::vector<std::uint64_t> &msg)
        {
            msg.resize(batch_encoder_->slot_count());
            randomize_array_mod(msg.data(), batch_encoder_->slot_count(), parms_.plain_modulus());
        }

        /**
        Create a vector of slot_count uniform random double precision values in [0, 1).
        */
        void randomize_message_double(std::vector<double> &msg)
        {
            msg.resize(ckks_encoder_->slot_count());
            std::generate(msg.begin(), msg.end(), []() { return static_cast<double>(std::rand()) / RAND_MAX; });
        }

    private:
        seal::EncryptionParameters parms_;
        seal::SEALContext context_;
        std::shared_ptr<seal::KeyGenerator> keygen_{ nullptr };
        std::shared_ptr<seal::Encryptor> encryptor_{ nullptr };
        std::shared_ptr<seal::Decryptor> decryptor_{ nullptr };
        std::shared_ptr<seal::BatchEncoder> batch_encoder_{ nullptr };
        std::shared_ptr<seal::CKKSEncoder> ckks_encoder_{ nullptr };
        std::shared_ptr<seal::Evaluator> evaluator_{ nullptr };

        /**
        The following data members are created as input/output containers for benchmark cases.
        This avoids repeated and unnecessary allocation/deallocation in benchmark runs.
        */
        seal::SecretKey sk_;
        seal::PublicKey pk_;
        seal::RelinKeys rlk_;
        seal::GaloisKeys glk_;
        std::vector<std::uint32_t> galois_elts_all_;
        std::vector<std::uint64_t> msg_uint64_;
        std::vector<double> msg_double_;
        std::vector<seal::Plaintext> pt_;
        std::vector<seal::Ciphertext> ct_;
    }; // namespace BMEnv

    // NTT benchmark cases
    void bm_util_ntt_forward(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_inverse(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_forward_low_level(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_inverse_low_level(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_forward_low_level_lazy(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_util_ntt_inverse_low_level_lazy(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // KeyGen benchmark cases
    void bm_keygen_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_keygen_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_keygen_relin(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_keygen_galois(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // BFV-specific benchmark cases
    void bm_bfv_encrypt_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_encrypt_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_decrypt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_encode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_decode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_add_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_add_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_negate(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_sub_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_sub_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_mul_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_mul_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_square(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_modswitch_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_relin_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_rotate_rows(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bfv_rotate_cols(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // BGV-specific benchmark cases
    void bm_bgv_encrypt_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_encrypt_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_decrypt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_encode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_decode_batch(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_negate(benchmark::State &state, std::shared_ptr<BMEnv>);
    void bm_bgv_negate_inplace(benchmark::State &state, std::shared_ptr<BMEnv>);
    void bm_bgv_add_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_add_ct_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_add_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_add_pt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_ct_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_mul_pt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_square(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_square_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_modswitch_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_relin_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_rows(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_rows_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_cols(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_rotate_cols_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_to_ntt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_bgv_from_ntt_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);

    // CKKS-specific benchmark cases
    void bm_ckks_encrypt_secret(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_encrypt_public(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_decrypt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_encode_double(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_decode_double(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_add_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_add_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_negate(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_sub_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_sub_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_mul_ct(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_mul_pt(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_square(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_rescale_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_relin_inplace(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);
    void bm_ckks_rotate(benchmark::State &state, std::shared_ptr<BMEnv> bm_env);



} // namespace sealbench



namespace gtest2gbenchmark{

    //batchencoder.cpp gtest2gbenchmark benchmarks
    void BatchEncoderTest_BatchUnbatchUIntVector(benchmark::State &state);
    void BatchEncoderTest_BatchUnbatchIntVector(benchmark::State &state);

    //ciphertext.cpp gtest2gbenchmark benchmarks
    void CiphertextTest_BFVCiphertextBasics(benchmark::State &state);
    void CiphertextTest_BFVSaveLoadCiphertext(benchmark::State &state);
    void CiphertextTest_BGVCiphertextBasics(benchmark::State &state);
    void CiphertextTest_BGVSaveLoadCiphertext(benchmark::State &state);

    // ckks.cpp gtest2gbenchmark benchmark 
    void CKKSEncoderTest_CKKSEncoderEncodeVectorDecodeTest(benchmark::State &state);
    void CKKSEncoderTest_CKKSEncoderEncodeSingleDecodeTest(benchmark::State &state);

    // context.cpp gtest2gbenchmark benchmark 
    void ContextTest_BFVContextConstructor(benchmark::State &state);
    void ContextTest_ModulusChainExpansion(benchmark::State &state);
    void EncryptionParameterQualifiersTest_BFVParameterError(benchmark::State &state);
    void ContextTest_BGVContextConstructor(benchmark::State &state);
    void EncryptionParameterQualifiersTest_BGVParameterError(benchmark::State &state);

    // dynarray.cpp gtest2gbenchmark benchmark 
    void DynArrayTest_DynArrayBasics(benchmark::State &state);
    void DynArrayTest_FromSpan(benchmark::State &state);
    void DynArrayTest_SaveLoadDynArray(benchmark::State &state);
    void DynArrayTest_Assign(benchmark::State &state);

    // encryptionparams.cpp gtest2gbenchmark benchmark 
    void EncryptionParametersTest_EncryptionParametersSet(benchmark::State &state);
    void EncryptionParametersTest_EncryptionParametersCompare(benchmark::State &state);
    void EncryptionParametersTest_EncryptionParametersSaveLoad(benchmark::State &state);

    // encryptor.cpp gtest2gbenchmark benchmark 
    void EncryptorTest_BFVEncryptDecrypt(benchmark::State &state);
    void EncryptorTest_BFVEncryptZeroDecrypt(benchmark::State &state);
    void EncryptorTest_CKKSEncryptZeroDecrypt(benchmark::State &state);
    void EncryptorTest_CKKSEncryptDecrypt(benchmark::State &state);
    void EncryptorTest_BGVEncryptDecrypt(benchmark::State &state);
    void EncryptorTest_BGVEncryptZeroDecrypt(benchmark::State &state);

    // evaluator.cpp gtest2gbenchmark benchmark 
    void EvaluatorTest_BFVEncryptNegateDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptAddDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptNegateDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptAddDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptAddDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptAddPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptSubPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptSubDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptAddPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptSubPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptMultiplyPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptMultiplyDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptSubDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptAddPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptSubPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptMultiplyPlainDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptMultiplyDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVRelinearize(benchmark::State &state);
    void EvaluatorTest_BGVRelinearize(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptNaiveMultiplyDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptMultiplyByNumberDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptMultiplyRelinDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptSquareRelinDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptMultiplyRelinRescaleDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptSquareRelinRescaleDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptModSwitchDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptMultiplyRelinRescaleModSwitchAddDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptRotateDecrypt(benchmark::State &state);
    void EvaluatorTest_CKKSEncryptRescaleRotateDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptSquareDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptMultiplyManyDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptExponentiateDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptAddManyDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptSquareDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptMultiplyManyDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptExponentiateDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptAddManyDecrypt(benchmark::State &state);
    void EvaluatorTest_TransformPlainToNTT(benchmark::State &state);
    void EvaluatorTest_TransformEncryptedToFromNTT(benchmark::State &state);
    void EvaluatorTest_BFVEncryptMultiplyPlainNTTDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptApplyGaloisDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptRotateMatrixDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptModSwitchToNextDecrypt(benchmark::State &state);
    void EvaluatorTest_BFVEncryptModSwitchToDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptMultiplyPlainNTTDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptApplyGaloisDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptRotateMatrixDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptModSwitchToNextDecrypt(benchmark::State &state);
    void EvaluatorTest_BGVEncryptModSwitchToDecrypt(benchmark::State &state);

    // galoiskeys.cpp gtest2gbenchmark benchmark 
    void GaloisKeysTest_GaloisKeysSaveLoad(benchmark::State &state);
    void GaloisKeysTest_GaloisKeysSeededSaveLoad(benchmark::State &state);

    // keygenerator.cpp gtest2gbenchmark benchmark 
    void KeyGeneratorTest_BFVKeyGeneration(benchmark::State &state);
    void KeyGeneratorTest_BGVKeyGeneration(benchmark::State &state);
    void KeyGeneratorTest_CKKSKeyGeneration(benchmark::State &state);
    void KeyGeneratorTest_Constructors(benchmark::State &state);

    // memorymanager.cpp gtest2gbenchmark benchmark
    void MemoryPoolHandleTest_MemoryPoolHandleConstructAssign(benchmark::State &state);
    void MemoryPoolHandleTest_MemoryPoolHandleAllocate(benchmark::State &state);
    void MemoryPoolHandleTest_UseCount(benchmark::State &state);

    // modulus.cpp gtest2gbenchmark benchmark
    void ModulusTest_CreateModulus(benchmark::State &state);
    void ModulusTest_CompareModulus(benchmark::State &state);
    void ModulusTest_SaveLoadModulus(benchmark::State &state);
    void ModulusTest_Reduce(benchmark::State &state);
    void CoeffModTest_CustomExceptionTest(benchmark::State &state);
    void CoeffModTest_CustomTest(benchmark::State &state);

    // plaintext.cpp gtest2gbenchmark benchmark
    void PlaintextTest_PlaintextBasics(benchmark::State &state);
    void PlaintextTest_FromSpan(benchmark::State &state);
    void PlaintextTest_SaveLoadPlaintext(benchmark::State &state);

    // publickey.cpp gtest2gbenchmark benchmark
    void PublicKeyTest_SaveLoadPublicKey(benchmark::State &state);

    // randomgen.cpp gtest2gbenchmark benchmark
    void RandomGenerator_UniformRandomCreateDefault(benchmark::State &state);
    void RandomGenerator_RandomGeneratorFactorySeed(benchmark::State &state);
    void RandomGenerator_SequentialRandomGenerator(benchmark::State &state);
    void RandomGenerator_RandomUInt64(benchmark::State &state);
    void RandomGenerator_SeededRNG(benchmark::State &state);
    void RandomGenerator_RandomSeededRNG(benchmark::State &state);
    void RandomGenerator_MultiThreaded(benchmark::State &state);
    void RandomGenerator_UniformRandomGeneratorInfo(benchmark::State &state);
    void RandomGenerator_UniformRandomGeneratorInfoSaveLoad(benchmark::State &state);

    // randomtostd.cpp gtest2gbenchmark benchmark
    void RandomToStandard_RandomToStandardGenerate(benchmark::State &state);

    // relinkeys.cpp gtest2gbenchmark benchmark
    void RelinKeysTest_RelinKeysSaveLoad(benchmark::State &state);
    void RelinKeysTest_RelinKeysSeededSaveLoad(benchmark::State &state);

    // secretkey.cpp gtest2gbenchmark benchmark
    void SecretKeyTest_SaveLoadSecretKey(benchmark::State &state);

    // serialization.cpp gtest2gbenchmark benchmark
    void SerializationTest_IsValidHeader(benchmark::State &state);
    void SerializationTest_SEALHeaderSaveLoad(benchmark::State &state);
    void SerializationTest_SaveLoadToStream(benchmark::State &state);
    void SerializationTest_SaveLoadToBuffer(benchmark::State &state);

    namespace util{
    // util::clipnormal.cpp gtest2gbenchmark benchmark
        void ClipNormal_ClipNormalGenerate(benchmark::State &state);

    // util::common.cpp gtest2gbenchmark benchmark
        void Common_Constants(benchmark::State &state);
        void Common_UnsignedComparisons(benchmark::State &state);
        void Common_SafeArithmetic(benchmark::State &state);
        void Common_FitsIn(benchmark::State &state);
        void Common_DivideRoundUp(benchmark::State &state);
        void Common_HammingWeight(benchmark::State &state);
        void Common_ReverseBits32(benchmark::State &state);
        void Common_ReverseBits64(benchmark::State &state);
        void Common_GetSignificantBitCount(benchmark::State &state);
        void Common_GetMSBIndexGeneric(benchmark::State &state);

    // util::galois.cpp gtest2gbenchmark benchmark
        void GaloisToolTest_Create(benchmark::State &state);
        void GaloisToolTest_EltFromStep(benchmark::State &state);
        void GaloisToolTest_EltsFromSteps(benchmark::State &state);
        void GaloisToolTest_EltsAll(benchmark::State &state);
        void GaloisToolTest_IndexFromElt(benchmark::State &state);
        void GaloisToolTest_ApplyGalois(benchmark::State &state);
        void GaloisToolTest_ApplyGaloisNTT(benchmark::State &state);

    // util::hash.cpp gtest2gbenchmark benchmark
        void HashTest_Hash(benchmark::State &state);

    // util::iterator.cpp gtest2gbenchmark benchmark
        void IteratorTest_IterType(benchmark::State &state);
        void IteratorTest_Iterate(benchmark::State &state);
        void IteratorTest_SeqIter(benchmark::State &state);
        void IteratorTest_PtrIter(benchmark::State &state);
        void IteratorTest_StrideIter(benchmark::State &state);
        void IteratorTest_RNSIter(benchmark::State &state);
        void IteratorTest_PolyIter(benchmark::State &state);
        void IteratorTest_IterTuple(benchmark::State &state);
        void IteratorTest_ReverseIter(benchmark::State &state);

    // util::locks.cpp gtest2gbenchmark benchmark
        void ReaderWriterLockerTests_ReaderWriterLockNonBlocking(benchmark::State &state);
        void ReaderWriterLockerTests_ReaderWriterLockBlocking(benchmark::State &state);

    // util::mempool.cpp gtest2gbenchmark benchmark
        void MemoryPoolTest_TestMemoryPoolMT(benchmark::State &state);
        void MemoryPoolTests_PointerTestsMT(benchmark::State &state);
        void MemoryPoolTests_TestMemoryPoolST(benchmark::State &state);
        void MemoryPoolTests_PointerTestsST(benchmark::State &state);
        void MemoryPoolTests_Allocate(benchmark::State &state);

    // util::ntt.cpp gtest2gbenchmark benchmark
        void NTTTablesTest_NTTBasics(benchmark::State &state);
        void NTTTablesTest_NTTPrimitiveRootsTest(benchmark::State &state);
        void NTTTablesTest_NegacyclicNTTTest(benchmark::State &state);
        void NTTTablesTest_InverseNegacyclicNTTTest(benchmark::State &state);

    // util::numth.cpp gtest2gbenchmark benchmark
        void NumberTheory_GCD(benchmark::State &state);
        void NumberTheory_ExtendedGCD(benchmark::State &state);
        void NumberTheory_TryInvertUIntMod(benchmark::State &state);
        void NumberTheory_IsPrime(benchmark::State &state);
        void NumberTheory_NAF(benchmark::State &state);
        void NumberTheory_TryPrimitiveRootMod(benchmark::State &state);
        void NumberTheory_IsPrimitiveRootMod(benchmark::State &state);
        void NumberTheory_TryMinimalPrimitiveRootMod(benchmark::State &state);

    // util::polyarithsmallmod.cpp gtest2gbenchmark benchmark
        void PolyArithSmallMod_ModuloPolyCoeffs(benchmark::State &state);
        void PolyArithSmallMod_NegatePolyCoeffMod(benchmark::State &state);
        void PolyArithSmallMod_AddPolyCoeffMod(benchmark::State &state);
        void PolyArithSmallMod_SubPolyCoeffMod(benchmark::State &state);
        void PolyArithSmallMod_MultiplyPolyScalarCoeffMod(benchmark::State &state);
        void PolyArithSmallMod_MultiplyPolyMonoCoeffMod(benchmark::State &state);
        void PolyArithSmallMod_DyadicProductCoeffMod(benchmark::State &state);
        void PolyArithSmallMod_PolyInftyNormCoeffMod(benchmark::State &state);
        void PolyArithSmallMod_NegacyclicShiftPolyCoeffMod(benchmark::State &state);

    // util::polycore.cpp gtest2gbenchmark benchmark
        void PolyCore_AllocatePoly(benchmark::State &state);
        void PolyCore_SetZeroPoly(benchmark::State &state);
        void PolyCore_AllocateZeroPoly(benchmark::State &state);
        void PolyCore_AllocatePolyArray(benchmark::State &state);
        void PolyCore_SetZeroPolyArray(benchmark::State &state);
        void PolyCore_AllocateZeroPolyArray(benchmark::State &state);
        void PolyCore_SetPoly(benchmark::State &state);
        void PolyCore_SetPolyArray(benchmark::State &state);

    // util::rns.cpp gtest2gbenchmark benchmark
        void RNSBaseTest_Create(benchmark::State &state);
        void RNSBaseTest_ArrayAccess(benchmark::State &state);
        void RNSBaseTest_Copy(benchmark::State &state);
        void RNSBaseTest_Contains(benchmark::State &state);
        void RNSBaseTest_IsSubbaseOf(benchmark::State &state);
        void RNSBaseTest_Extend(benchmark::State &state);
        void RNSBaseTest_Drop(benchmark::State &state);
        void RNSBaseTest_ComposeDecompose(benchmark::State &state);
        void RNSBaseTest_ComposeDecomposeArray(benchmark::State &state);
        void BaseConverterTest_Initialize(benchmark::State &state);
        void BaseConverterTest_Convert(benchmark::State &state);
        void BaseConverterTest_ConvertArray(benchmark::State &state);
        void RNSToolTest_Initialize(benchmark::State &state);
        void RNSToolTest_FastBConvMTilde(benchmark::State &state);
        void RNSToolTest_MontgomeryReduction(benchmark::State &state);
        void RNSToolTest_FastFloor(benchmark::State &state);
        void RNSToolTest_FastBConvSK(benchmark::State &state);
        void RNSToolTest_ExactScaleAndRound(benchmark::State &state);
        void RNSToolTest_DivideAndRoundQLastInplace(benchmark::State &state);
        void RNSToolTest_DivideAndRoundQLastNTTInplace(benchmark::State &state);

    // util::stringtouint64.cpp gtest2gbenchmark benchmark
        void StringToUInt64_IsHexCharTest(benchmark::State &state);
        void StringToUInt64_HexToNibbleTest(benchmark::State &state);
        void StringToUInt64_GetHexStringBitCount(benchmark::State &state);
        void StringToUInt64_HexStringToUInt64(benchmark::State &state);

    // util::uint64tostring.cpp gtest2gbenchmark benchmark
        void UInt64ToString_NibbleToUpperHexTest(benchmark::State &state);
        void UInt64ToString_UInt64ToHexString(benchmark::State &state);
        void UInt64ToString_UInt64ToDecString(benchmark::State &state);
        void UInt64ToString_PolyToHexString(benchmark::State &state);

    // util::uintarith.cpp gtest2gbenchmark benchmark
        void UIntArith_AddUInt64Generic(benchmark::State &state);
        void UIntArith_AddUInt64(benchmark::State &state);
        void UIntArith_SubUInt64Generic(benchmark::State &state);
        void UIntArith_SubUInt64(benchmark::State &state);
        void UIntArith_AddUInt128(benchmark::State &state);
        void UIntArith_AddUInt(benchmark::State &state);
        void UIntArith_SubUInt(benchmark::State &state);
        void UIntArith_AddUIntUInt64(benchmark::State &state);
        void UIntArith_SubUIntUInt64(benchmark::State &state);
        void UIntArith_IncrementUInt(benchmark::State &state);
        void UIntArith_DecrementUInt(benchmark::State &state);
        void UIntArith_NegateUInt(benchmark::State &state);
        void UIntArith_LeftShiftUInt(benchmark::State &state);
        void UIntArith_LeftShiftUInt128(benchmark::State &state);
        void UIntArith_LeftShiftUInt192(benchmark::State &state);
        void UIntArith_RightShiftUInt(benchmark::State &state);
        void UIntArith_RightShiftUInt128(benchmark::State &state);
        void UIntArith_RightShiftUInt192(benchmark::State &state);
        void UIntArith_HalfRoundUpUInt(benchmark::State &state);
        void UIntArith_NotUInt(benchmark::State &state);
        void UIntArith_AndUInt(benchmark::State &state);
        void UIntArith_OrUInt(benchmark::State &state);
        void UIntArith_XorUInt(benchmark::State &state);
        void UIntArith_MultiplyUInt64Generic(benchmark::State &state);
        void UIntArith_MultiplyUInt64(benchmark::State &state);
        void UIntArith_MultiplyUInt64HW64Generic(benchmark::State &state);
        void UIntArith_MultiplyUInt64HW64(benchmark::State &state);
        void UIntArith_MultiplyManyUInt64(benchmark::State &state);
        void UIntArith_MultiplyManyUInt64Except(benchmark::State &state);
        void UIntArith_MultiplyUInt(benchmark::State &state);
        void UIntArith_MultiplyUIntUInt64(benchmark::State &state);
        void UIntArith_DivideUInt(benchmark::State &state);
        void UIntArith_DivideUInt128UInt64(benchmark::State &state);
        void UIntArith_DivideUInt192UInt64(benchmark::State &state);
        void UIntArith_ExponentiateUInt64(benchmark::State &state);

    // util::uintarithmod.cpp gtest2gbenchmark benchmark
        void UIntArithMod_IncrementUIntMod(benchmark::State &state);
        void UIntArithMod_DecrementUIntMod(benchmark::State &state);
        void UIntArithMod_NegateUIntMod(benchmark::State &state);
        void UIntArithMod_Div2UIntMod(benchmark::State &state);
        void UIntArithMod_AddUIntMod(benchmark::State &state);
        void UIntArithMod_SubUIntMod(benchmark::State &state);
        void UIntArithMod_TryInvertUIntMod(benchmark::State &state);

    // util::uintarithsmallmod.cpp gtest2gbenchmark benchmark
        void UIntArithSmallMod_IncrementUIntMod(benchmark::State &state);
        void UIntArithSmallMod_DecrementUIntMod(benchmark::State &state);
        void UIntArithSmallMod_NegateUIntMod(benchmark::State &state);
        void UIntArithSmallMod_Div2UIntMod(benchmark::State &state);
        void UIntArithSmallMod_AddUIntMod(benchmark::State &state);
        void UIntArithSmallMod_SubUIntMod(benchmark::State &state);
        void UIntArithSmallMod_BarrettReduce128(benchmark::State &state);
        void UIntArithSmallMod_MultiplyUIntMod(benchmark::State &state);
        void UIntArithSmallMod_MultiplyAddMod(benchmark::State &state);
        void UIntArithSmallMod_ModuloUIntMod(benchmark::State &state);
        void UIntArithSmallMod_TryInvertUIntMod(benchmark::State &state);
        void UIntArithSmallMod_ExponentiateUIntMod(benchmark::State &state);
        void UIntArithSmallMod_DotProductMod(benchmark::State &state);
        void UIntArithSmallMod_MultiplyUIntModOperand(benchmark::State &state);
        void UIntArithSmallMod_MultiplyUIntMod2(benchmark::State &state);
        void UIntArithSmallMod_MultiplyUIntModLazy(benchmark::State &state);
        void UIntArithSmallMod_MultiplyAddMod2(benchmark::State &state);

    // util::uintcore.cpp gtest2gbenchmark benchmark
        void UIntCore_AllocateUInt(benchmark::State &state);
        void UIntCore_SetZeroUInt(benchmark::State &state);
        void UIntCore_AllocateZeroUInt(benchmark::State &state);
        void UIntCore_SetUInt(benchmark::State &state);
        void UIntCore_SetUInt2(benchmark::State &state);
        void UIntCore_SetUInt3(benchmark::State &state);
        void UIntCore_IsZeroUInt(benchmark::State &state);
        void UIntCore_IsEqualUInt(benchmark::State &state);
        void UIntCore_IsBitSetUInt(benchmark::State &state);
        void UIntCore_IsHighBitSetUInt(benchmark::State &state);
        void UIntCore_SetBitUInt(benchmark::State &state);
        void UIntCore_GetSignificantBitCountUInt(benchmark::State &state);
        void UIntCore_GetSignificantUInt64CountUInt(benchmark::State &state);
        void UIntCore_GetNonzeroUInt64CountUInt(benchmark::State &state);
        void UIntCore_FilterHighBitsUInt(benchmark::State &state);
        void UIntCore_CompareUInt(benchmark::State &state);
        void UIntCore_GetPowerOfTwo(benchmark::State &state);
        void UIntCore_DuplicateUIntIfNeeded(benchmark::State &state);
    }

}
