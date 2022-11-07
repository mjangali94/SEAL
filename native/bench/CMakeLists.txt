# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.13)

project(SEALBench VERSION 4.0.0 LANGUAGES CXX)

# If not called from root CMakeLists.txt
if(NOT DEFINED SEAL_BUILD_BENCH)
    set(SEAL_BUILD_BENCH ON)

    # Import Microsoft SEAL
    find_package(SEAL 4.0.0 EXACT REQUIRED)

    # Must define these variables and include macros
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${OUTLIB_PATH})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
    set(SEAL_THIRDPARTY_DIR ${CMAKE_CURRENT_LIST_DIR}/../../thirdparty)
    set(THIRDPARTY_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/thirdparty)
    include(FetchContent)
    mark_as_advanced(FETCHCONTENT_BASE_DIR)
    mark_as_advanced(FETCHCONTENT_FULLY_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_UPDATES_DISCONNECTED)
    mark_as_advanced(FETCHCONTENT_QUIET)
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/../../cmake)
    include(SEALMacros)
else()
    set(THIRDPARTY_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/../../thirdparty)
endif()

if(NOT DEFINED SEAL_BUILD_DEPS)
    # [option] SEAL_BUILD_DEPS (default: ON)
    # Download and build missing dependencies, throw error if disabled.
    set(SEAL_BUILD_DEPS_OPTION_STR "Automatically download and build unmet dependencies")
    option(SEAL_BUILD_DEPS ${SEAL_BUILD_DEPS_OPTION_STR} ON)
endif()

# if SEAL_BUILD_BENCH is ON, use GoogleBenchmark
if(SEAL_BUILD_BENCH)
    if(SEAL_BUILD_DEPS)
        seal_fetch_thirdparty_content(ExternalBenchmark)
        seal_fetch_thirdparty_content(ExternalGTest)
        add_library(GTest::gtest ALIAS gtest)
    else()
        find_package(benchmark REQUIRED)
        if(NOT benchmark_FOUND)
            message(FATAL_ERROR "GoogleBenchmark: not found")
        else()
            message(STATUS "GoogleBenchmark: found")
        endif()
        find_package(GTest 1.10.0 REQUIRED)
        if(NOT GTest_FOUND)
            message(FATAL_ERROR "GoogleTest: not found")
        else()
            message(STATUS "GoogleTest: found")
        endif()
    endif()

    add_executable(sealbench)
    add_executable(gtest2gbenchmark)
    # If we're targeting WASM, add the appropriate link flags
    if(EMSCRIPTEN)
        set_target_properties(sealbench PROPERTIES LINK_FLAGS "-flto -O3 -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s MAXIMUM_MEMORY=4GB")
        set_target_properties(gtest2gbenchmark PROPERTIES LINK_FLAGS "-flto -O3 -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s MAXIMUM_MEMORY=4GB")
    endif()
    target_sources(sealbench
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/bench.cpp
            ${CMAKE_CURRENT_LIST_DIR}/keygen.cpp
            ${CMAKE_CURRENT_LIST_DIR}/ntt.cpp
            ${CMAKE_CURRENT_LIST_DIR}/bfv.cpp
            ${CMAKE_CURRENT_LIST_DIR}/bgv.cpp
            ${CMAKE_CURRENT_LIST_DIR}/ckks.cpp
    )
    target_sources(gtest2gbenchmark
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/gtest2gbenchmark.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/batchencoder.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/ciphertext.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/ckks.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/context.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/encryptionparams.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/encryptor.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/evaluator.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/galoiskeys.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/dynarray.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/keygenerator.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/memorymanager.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/modulus.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/plaintext.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/publickey.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/randomgen.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/randomtostd.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/relinkeys.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/secretkey.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/serialization.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/clipnormal.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/common.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/galois.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/hash.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/iterator.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/locks.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/mempool.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/numth.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/polyarithsmallmod.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/polycore.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/rns.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/ntt.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/stringtouint64.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/uint64tostring.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/uintarith.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/uintarithmod.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/uintarithsmallmod.cpp
            ${CMAKE_CURRENT_LIST_DIR}/gtest2gbenchmark/util/uintcore.cpp
    )

    if(TARGET SEAL::seal)
        target_link_libraries(sealbench PRIVATE SEAL::seal GTest::gtest)
        target_link_libraries(sealbench PRIVATE SEAL::seal benchmark::benchmark)
        target_link_libraries(gtest2gbenchmark PRIVATE SEAL::seal GTest::gtest)
        target_link_libraries(gtest2gbenchmark PRIVATE SEAL::seal benchmark::benchmark)
    elseif(TARGET SEAL::seal_shared)
        target_link_libraries(sealbench PRIVATE SEAL::seal_shared benchmark::benchmark)
        target_link_libraries(sealbench PRIVATE SEAL::seal_shared GTest::gtest)
        target_link_libraries(gtest2gbenchmark PRIVATE SEAL::seal_shared benchmark::benchmark)
        target_link_libraries(gtest2gbenchmark PRIVATE SEAL::seal_shared GTest::gtest)
    else()
        message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
    endif()
endif()
