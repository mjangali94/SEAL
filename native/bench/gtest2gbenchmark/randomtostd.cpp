// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "seal/randomgen.h"
#include "seal/randomtostd.h"
#include <cstdint>
#include <memory>
#include "gtest/gtest.h"
#include "../bench.h"

using namespace seal;
using namespace std;
using namespace seal::util;
using namespace benchmark;
using namespace gtest2gbenchmark;

namespace gtest2gbenchmark
{
    void RandomToStandard_RandomToStandardGenerate(State &state)
    {
        for (auto _ : state)
        {
            state.PauseTiming();
            state.ResumeTiming();
            shared_ptr<UniformRandomGenerator> generator(UniformRandomGeneratorFactory::DefaultFactory()->create());
            RandomToStandardAdapter rand(generator);
            ASSERT_TRUE(rand.generator() == generator);
            ASSERT_EQ(static_cast<uint32_t>(0), rand.min());
            ASSERT_EQ(static_cast<uint32_t>(UINT32_MAX), rand.max());
            bool lower_half = false;
            bool upper_half = false;
            bool even = false;
            bool odd = false;
            for (int i = 0; i < 50; i++)
            {
                uint32_t value = rand();
                if (value < UINT32_MAX / 2)
                {
                    lower_half = true;
                }
                else
                {
                    upper_half = true;
                }
                if ((value % 2) == 0)
                {
                    even = true;
                }
                else
                {
                    odd = true;
                }
            }
            ASSERT_TRUE(lower_half);
            ASSERT_TRUE(upper_half);
            ASSERT_TRUE(even);
            ASSERT_TRUE(odd);
        }
    }
} // namespace gtest2gbenchmark
