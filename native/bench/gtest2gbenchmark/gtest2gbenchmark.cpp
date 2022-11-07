// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/seal.h"
#include "../bench.h"
#include <iomanip>

using namespace benchmark;
using namespace seal;
using namespace gtest2gbenchmark;
using namespace std;


namespace gtest2gbenchmark{
    #define SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(name, func)                                                  \
    benchmark::RegisterBenchmark(#name,                                                                                                 \
        [=](benchmark::State &st) { func(st); })                                                                    \
    ->Unit(benchmark::kNanosecond)                                                                               \
    ->Iterations(10);


    void register_bm_gtest2gbenchmark()
    {




            //batchencoder.cpp gtest2gbenchmark benchmarks
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(BatchEncoderTest_BatchUnbatchUIntVector,BatchEncoderTest_BatchUnbatchUIntVector);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(BatchEncoderTest_BatchUnbatchIntVector,BatchEncoderTest_BatchUnbatchIntVector);

    //ciphertext.cpp gtest2gbenchmark benchmarks
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CiphertextTest_BFVCiphertextBasics,CiphertextTest_BFVCiphertextBasics);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CiphertextTest_BFVSaveLoadCiphertext,CiphertextTest_BFVSaveLoadCiphertext);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CiphertextTest_BGVCiphertextBasics,CiphertextTest_BGVCiphertextBasics);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CiphertextTest_BGVSaveLoadCiphertext,CiphertextTest_BGVSaveLoadCiphertext);

    // ckks.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CKKSEncoderTest_CKKSEncoderEncodeVectorDecodeTest,CKKSEncoderTest_CKKSEncoderEncodeVectorDecodeTest);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CKKSEncoderTest_CKKSEncoderEncodeSingleDecodeTest,CKKSEncoderTest_CKKSEncoderEncodeSingleDecodeTest);

    // context.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ContextTest_BFVContextConstructor,ContextTest_BFVContextConstructor);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ContextTest_ModulusChainExpansion,ContextTest_ModulusChainExpansion);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptionParameterQualifiersTest_BFVParameterError,EncryptionParameterQualifiersTest_BFVParameterError);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ContextTest_BGVContextConstructor,ContextTest_BGVContextConstructor);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptionParameterQualifiersTest_BGVParameterError,EncryptionParameterQualifiersTest_BGVParameterError);

    // dynarray.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(DynArrayTest_DynArrayBasics,DynArrayTest_DynArrayBasics);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(DynArrayTest_FromSpan,DynArrayTest_FromSpan);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(DynArrayTest_SaveLoadDynArray,DynArrayTest_SaveLoadDynArray);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(DynArrayTest_Assign,DynArrayTest_Assign);

    // encryptionparams.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptionParametersTest_EncryptionParametersSet,EncryptionParametersTest_EncryptionParametersSet);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptionParametersTest_EncryptionParametersCompare,EncryptionParametersTest_EncryptionParametersCompare);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptionParametersTest_EncryptionParametersSaveLoad,EncryptionParametersTest_EncryptionParametersSaveLoad);

    // encryptor.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptorTest_BFVEncryptDecrypt,EncryptorTest_BFVEncryptDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptorTest_BFVEncryptZeroDecrypt,EncryptorTest_BFVEncryptZeroDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptorTest_CKKSEncryptZeroDecrypt,EncryptorTest_CKKSEncryptZeroDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptorTest_CKKSEncryptDecrypt,EncryptorTest_CKKSEncryptDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptorTest_BGVEncryptDecrypt,EncryptorTest_BGVEncryptDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EncryptorTest_BGVEncryptZeroDecrypt,EncryptorTest_BGVEncryptZeroDecrypt);

    // evaluator.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptNegateDecrypt,EvaluatorTest_BFVEncryptNegateDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptAddDecrypt,EvaluatorTest_BFVEncryptAddDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptNegateDecrypt,EvaluatorTest_BGVEncryptNegateDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptAddDecrypt,EvaluatorTest_BGVEncryptAddDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptAddDecrypt,EvaluatorTest_CKKSEncryptAddDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptAddPlainDecrypt,EvaluatorTest_CKKSEncryptAddPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptSubPlainDecrypt,EvaluatorTest_CKKSEncryptSubPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptSubDecrypt,EvaluatorTest_BFVEncryptSubDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptAddPlainDecrypt,EvaluatorTest_BFVEncryptAddPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptSubPlainDecrypt,EvaluatorTest_BFVEncryptSubPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptMultiplyPlainDecrypt,EvaluatorTest_BFVEncryptMultiplyPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptMultiplyDecrypt,EvaluatorTest_BFVEncryptMultiplyDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptSubDecrypt,EvaluatorTest_BGVEncryptSubDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptAddPlainDecrypt,EvaluatorTest_BGVEncryptAddPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptSubPlainDecrypt,EvaluatorTest_BGVEncryptSubPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptMultiplyPlainDecrypt,EvaluatorTest_BGVEncryptMultiplyPlainDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptMultiplyDecrypt,EvaluatorTest_BGVEncryptMultiplyDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVRelinearize,EvaluatorTest_BFVRelinearize);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVRelinearize,EvaluatorTest_BGVRelinearize);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptNaiveMultiplyDecrypt,EvaluatorTest_CKKSEncryptNaiveMultiplyDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptMultiplyByNumberDecrypt,EvaluatorTest_CKKSEncryptMultiplyByNumberDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptMultiplyRelinDecrypt,EvaluatorTest_CKKSEncryptMultiplyRelinDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptSquareRelinDecrypt,EvaluatorTest_CKKSEncryptSquareRelinDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptMultiplyRelinRescaleDecrypt,EvaluatorTest_CKKSEncryptMultiplyRelinRescaleDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptSquareRelinRescaleDecrypt,EvaluatorTest_CKKSEncryptSquareRelinRescaleDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptModSwitchDecrypt,EvaluatorTest_CKKSEncryptModSwitchDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptMultiplyRelinRescaleModSwitchAddDecrypt,EvaluatorTest_CKKSEncryptMultiplyRelinRescaleModSwitchAddDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptRotateDecrypt,EvaluatorTest_CKKSEncryptRotateDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_CKKSEncryptRescaleRotateDecrypt,EvaluatorTest_CKKSEncryptRescaleRotateDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptSquareDecrypt,EvaluatorTest_BFVEncryptSquareDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptMultiplyManyDecrypt,EvaluatorTest_BFVEncryptMultiplyManyDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptExponentiateDecrypt,EvaluatorTest_BFVEncryptExponentiateDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptAddManyDecrypt,EvaluatorTest_BFVEncryptAddManyDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptSquareDecrypt,EvaluatorTest_BGVEncryptSquareDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptMultiplyManyDecrypt,EvaluatorTest_BGVEncryptMultiplyManyDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptExponentiateDecrypt,EvaluatorTest_BGVEncryptExponentiateDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptAddManyDecrypt,EvaluatorTest_BGVEncryptAddManyDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_TransformPlainToNTT,EvaluatorTest_TransformPlainToNTT);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_TransformEncryptedToFromNTT,EvaluatorTest_TransformEncryptedToFromNTT);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptMultiplyPlainNTTDecrypt,EvaluatorTest_BFVEncryptMultiplyPlainNTTDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptApplyGaloisDecrypt,EvaluatorTest_BFVEncryptApplyGaloisDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptRotateMatrixDecrypt,EvaluatorTest_BFVEncryptRotateMatrixDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptModSwitchToNextDecrypt,EvaluatorTest_BFVEncryptModSwitchToNextDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BFVEncryptModSwitchToDecrypt,EvaluatorTest_BFVEncryptModSwitchToDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptMultiplyPlainNTTDecrypt,EvaluatorTest_BGVEncryptMultiplyPlainNTTDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptApplyGaloisDecrypt,EvaluatorTest_BGVEncryptApplyGaloisDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptRotateMatrixDecrypt,EvaluatorTest_BGVEncryptRotateMatrixDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptModSwitchToNextDecrypt,EvaluatorTest_BGVEncryptModSwitchToNextDecrypt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(EvaluatorTest_BGVEncryptModSwitchToDecrypt,EvaluatorTest_BGVEncryptModSwitchToDecrypt);

    // galoiskeys.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisKeysTest_GaloisKeysSaveLoad,GaloisKeysTest_GaloisKeysSaveLoad);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisKeysTest_GaloisKeysSeededSaveLoad,GaloisKeysTest_GaloisKeysSeededSaveLoad);

    // keygenerator.cpp gtest2gbenchmark benchmark 
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(KeyGeneratorTest_BFVKeyGeneration,KeyGeneratorTest_BFVKeyGeneration);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(KeyGeneratorTest_BGVKeyGeneration,KeyGeneratorTest_BGVKeyGeneration);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(KeyGeneratorTest_CKKSKeyGeneration,KeyGeneratorTest_CKKSKeyGeneration);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(KeyGeneratorTest_Constructors,KeyGeneratorTest_Constructors);

    // memorymanager.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolHandleTest_MemoryPoolHandleConstructAssign,MemoryPoolHandleTest_MemoryPoolHandleConstructAssign);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolHandleTest_MemoryPoolHandleAllocate,MemoryPoolHandleTest_MemoryPoolHandleAllocate);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolHandleTest_UseCount,MemoryPoolHandleTest_UseCount);

    // modulus.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ModulusTest_CreateModulus,ModulusTest_CreateModulus);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ModulusTest_CompareModulus,ModulusTest_CompareModulus);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ModulusTest_SaveLoadModulus,ModulusTest_SaveLoadModulus);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ModulusTest_Reduce,ModulusTest_Reduce);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CoeffModTest_CustomExceptionTest,CoeffModTest_CustomExceptionTest);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(CoeffModTest_CustomTest,CoeffModTest_CustomTest);

    // plaintext.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PlaintextTest_PlaintextBasics,PlaintextTest_PlaintextBasics);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PlaintextTest_FromSpan,PlaintextTest_FromSpan);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PlaintextTest_SaveLoadPlaintext,PlaintextTest_SaveLoadPlaintext);

    // publickey.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PublicKeyTest_SaveLoadPublicKey,PublicKeyTest_SaveLoadPublicKey);

    // randomgen.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_UniformRandomCreateDefault,RandomGenerator_UniformRandomCreateDefault);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_RandomGeneratorFactorySeed,RandomGenerator_RandomGeneratorFactorySeed);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_SequentialRandomGenerator,RandomGenerator_SequentialRandomGenerator);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_RandomUInt64,RandomGenerator_RandomUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_SeededRNG,RandomGenerator_SeededRNG);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_RandomSeededRNG,RandomGenerator_RandomSeededRNG);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_MultiThreaded,RandomGenerator_MultiThreaded);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_UniformRandomGeneratorInfo,RandomGenerator_UniformRandomGeneratorInfo);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomGenerator_UniformRandomGeneratorInfoSaveLoad,RandomGenerator_UniformRandomGeneratorInfoSaveLoad);

    // randomtostd.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RandomToStandard_RandomToStandardGenerate,RandomToStandard_RandomToStandardGenerate);

    // relinkeys.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RelinKeysTest_RelinKeysSaveLoad,RelinKeysTest_RelinKeysSaveLoad);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RelinKeysTest_RelinKeysSeededSaveLoad,RelinKeysTest_RelinKeysSeededSaveLoad);

    // secretkey.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(SecretKeyTest_SaveLoadSecretKey,SecretKeyTest_SaveLoadSecretKey);

    // serialization.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(SerializationTest_IsValidHeader,SerializationTest_IsValidHeader);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(SerializationTest_SEALHeaderSaveLoad,SerializationTest_SEALHeaderSaveLoad);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(SerializationTest_SaveLoadToStream,SerializationTest_SaveLoadToStream);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(SerializationTest_SaveLoadToBuffer,SerializationTest_SaveLoadToBuffer);


    // util::clipnormal.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ClipNormal_ClipNormalGenerate,util::ClipNormal_ClipNormalGenerate);

    // util::common.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_Constants,util::Common_Constants);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_UnsignedComparisons,util::Common_UnsignedComparisons);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_SafeArithmetic,util::Common_SafeArithmetic);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_FitsIn,util::Common_FitsIn);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_DivideRoundUp,util::Common_DivideRoundUp);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_HammingWeight,util::Common_HammingWeight);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_ReverseBits32,util::Common_ReverseBits32);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_ReverseBits64,util::Common_ReverseBits64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_GetSignificantBitCount,util::Common_GetSignificantBitCount);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(Common_GetMSBIndexGeneric,util::Common_GetMSBIndexGeneric);

    // util::galois.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisToolTest_Create,util::GaloisToolTest_Create);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisToolTest_EltFromStep,util::GaloisToolTest_EltFromStep);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisToolTest_EltsFromSteps,util::GaloisToolTest_EltsFromSteps);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisToolTest_EltsAll,util::GaloisToolTest_EltsAll);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisToolTest_IndexFromElt,util::GaloisToolTest_IndexFromElt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisToolTest_ApplyGalois,util::GaloisToolTest_ApplyGalois);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(GaloisToolTest_ApplyGaloisNTT,util::GaloisToolTest_ApplyGaloisNTT);

    // util::hash.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(HashTest_Hash,util::HashTest_Hash);

    // util::iterator.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_IterType,util::IteratorTest_IterType);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_Iterate,util::IteratorTest_Iterate);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_SeqIter,util::IteratorTest_SeqIter);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_PtrIter,util::IteratorTest_PtrIter);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_StrideIter,util::IteratorTest_StrideIter);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_RNSIter,util::IteratorTest_RNSIter);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_PolyIter,util::IteratorTest_PolyIter);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_IterTuple,util::IteratorTest_IterTuple);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(IteratorTest_ReverseIter,util::IteratorTest_ReverseIter);

    // util::locks.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ReaderWriterLockerTests_ReaderWriterLockNonBlocking,util::ReaderWriterLockerTests_ReaderWriterLockNonBlocking);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(ReaderWriterLockerTests_ReaderWriterLockBlocking,util::ReaderWriterLockerTests_ReaderWriterLockBlocking);

    // util::mempool.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolTest_TestMemoryPoolMT,util::MemoryPoolTest_TestMemoryPoolMT);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolTests_PointerTestsMT,util::MemoryPoolTests_PointerTestsMT);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolTests_TestMemoryPoolST,util::MemoryPoolTests_TestMemoryPoolST);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolTests_PointerTestsST,util::MemoryPoolTests_PointerTestsST);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(MemoryPoolTests_Allocate,util::MemoryPoolTests_Allocate);

    // util::ntt.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NTTTablesTest_NTTBasics,util::NTTTablesTest_NTTBasics);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NTTTablesTest_NTTPrimitiveRootsTest,util::NTTTablesTest_NTTPrimitiveRootsTest);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NTTTablesTest_NegacyclicNTTTest,util::NTTTablesTest_NegacyclicNTTTest);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NTTTablesTest_InverseNegacyclicNTTTest,util::NTTTablesTest_InverseNegacyclicNTTTest);

    // util::numth.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_GCD,util::NumberTheory_GCD);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_ExtendedGCD,util::NumberTheory_ExtendedGCD);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_TryInvertUIntMod,util::NumberTheory_TryInvertUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_IsPrime,util::NumberTheory_IsPrime);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_NAF,util::NumberTheory_NAF);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_TryPrimitiveRootMod,util::NumberTheory_TryPrimitiveRootMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_IsPrimitiveRootMod,util::NumberTheory_IsPrimitiveRootMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(NumberTheory_TryMinimalPrimitiveRootMod,util::NumberTheory_TryMinimalPrimitiveRootMod);

    // util::polyarithsmallmod.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_ModuloPolyCoeffs,util::PolyArithSmallMod_ModuloPolyCoeffs);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_NegatePolyCoeffMod,util::PolyArithSmallMod_NegatePolyCoeffMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_AddPolyCoeffMod,util::PolyArithSmallMod_AddPolyCoeffMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_SubPolyCoeffMod,util::PolyArithSmallMod_SubPolyCoeffMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_MultiplyPolyScalarCoeffMod,util::PolyArithSmallMod_MultiplyPolyScalarCoeffMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_MultiplyPolyMonoCoeffMod,util::PolyArithSmallMod_MultiplyPolyMonoCoeffMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_DyadicProductCoeffMod,util::PolyArithSmallMod_DyadicProductCoeffMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_PolyInftyNormCoeffMod,util::PolyArithSmallMod_PolyInftyNormCoeffMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyArithSmallMod_NegacyclicShiftPolyCoeffMod,util::PolyArithSmallMod_NegacyclicShiftPolyCoeffMod);

    // util::polycore.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_AllocatePoly,util::PolyCore_AllocatePoly);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_SetZeroPoly,util::PolyCore_SetZeroPoly);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_AllocateZeroPoly,util::PolyCore_AllocateZeroPoly);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_AllocatePolyArray,util::PolyCore_AllocatePolyArray);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_SetZeroPolyArray,util::PolyCore_SetZeroPolyArray);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_AllocateZeroPolyArray,util::PolyCore_AllocateZeroPolyArray);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_SetPoly,util::PolyCore_SetPoly);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(PolyCore_SetPolyArray,util::PolyCore_SetPolyArray);

    // util::rns.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_Create,util::RNSBaseTest_Create);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_ArrayAccess,util::RNSBaseTest_ArrayAccess);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_Copy,util::RNSBaseTest_Copy);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_Contains,util::RNSBaseTest_Contains);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_IsSubbaseOf,util::RNSBaseTest_IsSubbaseOf);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_Extend,util::RNSBaseTest_Extend);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_Drop,util::RNSBaseTest_Drop);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_ComposeDecompose,util::RNSBaseTest_ComposeDecompose);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSBaseTest_ComposeDecomposeArray,util::RNSBaseTest_ComposeDecomposeArray);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(BaseConverterTest_Initialize,util::BaseConverterTest_Initialize);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(BaseConverterTest_Convert,util::BaseConverterTest_Convert);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(BaseConverterTest_ConvertArray,util::BaseConverterTest_ConvertArray);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_Initialize,util::RNSToolTest_Initialize);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_FastBConvMTilde,util::RNSToolTest_FastBConvMTilde);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_MontgomeryReduction,util::RNSToolTest_MontgomeryReduction);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_FastFloor,util::RNSToolTest_FastFloor);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_FastBConvSK,util::RNSToolTest_FastBConvSK);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_ExactScaleAndRound,util::RNSToolTest_ExactScaleAndRound);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_DivideAndRoundQLastInplace,util::RNSToolTest_DivideAndRoundQLastInplace);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(RNSToolTest_DivideAndRoundQLastNTTInplace,util::RNSToolTest_DivideAndRoundQLastNTTInplace);

    // util::stringtouint64.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(StringToUInt64_IsHexCharTest,util::StringToUInt64_IsHexCharTest);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(StringToUInt64_HexToNibbleTest,util::StringToUInt64_HexToNibbleTest);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(StringToUInt64_GetHexStringBitCount,util::StringToUInt64_GetHexStringBitCount);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(StringToUInt64_HexStringToUInt64,util::StringToUInt64_HexStringToUInt64);

    // util::uint64tostring.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UInt64ToString_NibbleToUpperHexTest,util::UInt64ToString_NibbleToUpperHexTest);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UInt64ToString_UInt64ToHexString,util::UInt64ToString_UInt64ToHexString);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UInt64ToString_UInt64ToDecString,util::UInt64ToString_UInt64ToDecString);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UInt64ToString_PolyToHexString,util::UInt64ToString_PolyToHexString);

    // util::uintarith.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_AddUInt64Generic,util::UIntArith_AddUInt64Generic);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_AddUInt64,util::UIntArith_AddUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_SubUInt64Generic,util::UIntArith_SubUInt64Generic);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_SubUInt64,util::UIntArith_SubUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_AddUInt128,util::UIntArith_AddUInt128);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_AddUInt,util::UIntArith_AddUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_SubUInt,util::UIntArith_SubUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_AddUIntUInt64,util::UIntArith_AddUIntUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_SubUIntUInt64,util::UIntArith_SubUIntUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_IncrementUInt,util::UIntArith_IncrementUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_DecrementUInt,util::UIntArith_DecrementUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_NegateUInt,util::UIntArith_NegateUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_LeftShiftUInt,util::UIntArith_LeftShiftUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_LeftShiftUInt128,util::UIntArith_LeftShiftUInt128);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_LeftShiftUInt192,util::UIntArith_LeftShiftUInt192);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_RightShiftUInt,util::UIntArith_RightShiftUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_RightShiftUInt128,util::UIntArith_RightShiftUInt128);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_RightShiftUInt192,util::UIntArith_RightShiftUInt192);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_HalfRoundUpUInt,util::UIntArith_HalfRoundUpUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_NotUInt,util::UIntArith_NotUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_AndUInt,util::UIntArith_AndUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_OrUInt,util::UIntArith_OrUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_XorUInt,util::UIntArith_XorUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyUInt64Generic,util::UIntArith_MultiplyUInt64Generic);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyUInt64,util::UIntArith_MultiplyUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyUInt64HW64Generic,util::UIntArith_MultiplyUInt64HW64Generic);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyUInt64HW64,util::UIntArith_MultiplyUInt64HW64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyManyUInt64,util::UIntArith_MultiplyManyUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyManyUInt64Except,util::UIntArith_MultiplyManyUInt64Except);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyUInt,util::UIntArith_MultiplyUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_MultiplyUIntUInt64,util::UIntArith_MultiplyUIntUInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_DivideUInt,util::UIntArith_DivideUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_DivideUInt128UInt64,util::UIntArith_DivideUInt128UInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_DivideUInt192UInt64,util::UIntArith_DivideUInt192UInt64);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArith_ExponentiateUInt64,util::UIntArith_ExponentiateUInt64);

    // util::uintarithmod.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithMod_IncrementUIntMod,util::UIntArithMod_IncrementUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithMod_DecrementUIntMod,util::UIntArithMod_DecrementUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithMod_NegateUIntMod,util::UIntArithMod_NegateUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithMod_Div2UIntMod,util::UIntArithMod_Div2UIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithMod_AddUIntMod,util::UIntArithMod_AddUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithMod_SubUIntMod,util::UIntArithMod_SubUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithMod_TryInvertUIntMod,util::UIntArithMod_TryInvertUIntMod);

    // util::uintarithsmallmod.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_IncrementUIntMod,util::UIntArithSmallMod_IncrementUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_DecrementUIntMod,util::UIntArithSmallMod_DecrementUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_NegateUIntMod,util::UIntArithSmallMod_NegateUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_Div2UIntMod,util::UIntArithSmallMod_Div2UIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_AddUIntMod,util::UIntArithSmallMod_AddUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_SubUIntMod,util::UIntArithSmallMod_SubUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_BarrettReduce128,util::UIntArithSmallMod_BarrettReduce128);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_MultiplyUIntMod,util::UIntArithSmallMod_MultiplyUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_MultiplyAddMod,util::UIntArithSmallMod_MultiplyAddMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_ModuloUIntMod,util::UIntArithSmallMod_ModuloUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_TryInvertUIntMod,util::UIntArithSmallMod_TryInvertUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_ExponentiateUIntMod,util::UIntArithSmallMod_ExponentiateUIntMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_DotProductMod,util::UIntArithSmallMod_DotProductMod);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_MultiplyUIntModOperand,util::UIntArithSmallMod_MultiplyUIntModOperand);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_MultiplyUIntMod2,util::UIntArithSmallMod_MultiplyUIntMod2);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_MultiplyUIntModLazy,util::UIntArithSmallMod_MultiplyUIntModLazy);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntArithSmallMod_MultiplyAddMod2,util::UIntArithSmallMod_MultiplyAddMod2);

    // util::uintcore.cpp gtest2gbenchmark benchmark
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_AllocateUInt,util::UIntCore_AllocateUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_SetZeroUInt,util::UIntCore_SetZeroUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_AllocateZeroUInt,util::UIntCore_AllocateZeroUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_SetUInt,util::UIntCore_SetUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_SetUInt2,util::UIntCore_SetUInt2);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_SetUInt3,util::UIntCore_SetUInt3);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_IsZeroUInt,util::UIntCore_IsZeroUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_IsEqualUInt,util::UIntCore_IsEqualUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_IsBitSetUInt,util::UIntCore_IsBitSetUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_IsHighBitSetUInt,util::UIntCore_IsHighBitSetUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_SetBitUInt,util::UIntCore_SetBitUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_GetSignificantBitCountUInt,util::UIntCore_GetSignificantBitCountUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_GetSignificantUInt64CountUInt,util::UIntCore_GetSignificantUInt64CountUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_GetNonzeroUInt64CountUInt,util::UIntCore_GetNonzeroUInt64CountUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_FilterHighBitsUInt,util::UIntCore_FilterHighBitsUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_CompareUInt,util::UIntCore_CompareUInt);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_GetPowerOfTwo,util::UIntCore_GetPowerOfTwo);
        SEAL_BENCHMARK_REGISTER_GTEST2GBENCHMARK(UIntCore_DuplicateUIntIfNeeded,util::UIntCore_DuplicateUIntIfNeeded);

    }

}// namespace gtest2gbenchmark

int main(int argc, char **argv)
{

    gtest2gbenchmark::register_bm_gtest2gbenchmark();


    benchmark::RunSpecifiedBenchmarks();

}
