/**
 * @file   merkle_damgard.hpp
 * @brief  Generic Merkle-Damgard hash construction and MD5.
 * @author Ugur Altinisik - altnskuur
 */

#pragma once
#include <array>

namespace crypto::hash 
{    
    namespace construction 
    {
        /**
         * @brief Generic Merkle-Damgard Hash Construction.
         * 
         * @details
         * Builds a hash function for arbitrary-length messages from a
         * fixed-size compression function f:
         *   -# Start with the IV as the initial state.
         *   -# Pad the message to a multiple of the block size.
         *   -# Split it into blocks.
         *   -# For each block: state = f(state, block).
         *   -# Encode the final state as bytes in the algorithm's byte order.
         *
         * Subclasses provide the IV, compress() and bigEndian().
         *
         * @tparam WordType    Word type of the state (e.g. uint32_t for MD5).
         * @tparam StateWords  Number of words in the state (4 for MD5).
         * @tparam BlockSize   Message block size in bytes (64 for MD5).
         * @tparam LengthBytes Size of the length field in bytes (8 for MD5).
         */
        template <typename WordType, std::size_t StateWords, std::size_t BlockSize, std::size_t LengthBytes = 8>
        class MerkleDamgard 
        {

            public:
                using State = std::array<WordType, StateWords>;
                using Block = std::array<std::uint8_t, BlockSize>;


            private:
                State m_iv;                 // Initialization vector
                State m_state;              // Current state vector
                Block m_buffer{};           // Buffer for partial blocks
                std::size_t m_bufLen    = 0;   // Length of data in buffer
                std::size_t m_totalLen  = 0; // Total length of the message

                /**
                 * @brief Builds the final padded block(s) from the buffered bytes.
                 * @return One block, or two if the length field does not fit in the first.
                 */
                std::vector<Block> pad() const 
                {
                    std::vector<Block> blocks(1); // one all-zero block

                }
            protected: 
                /**
                 * @brief Initializes the state with the algorithm's IV.
                 * @param iv Initial chaining value defined by the concrete hash.
                 */
                explicit MerkleDamgard(const State& iv) : m_iv(iv), m_state(iv) { }

                /**
                 * @brief Compresses a single block into the state.
                 * @param state The current state to be updated.
                 * @param block The message block to compress.
                 */
                virtual void compress(State& state, const Block& block) const = 0;

            public:
                /**
                 * @brief Virtual destructor for the Merkle-Damgard class.
                 */
                virtual ~MerkleDamgard() = default;

                /**
                 * @brief Compresses a single block into the state.
                 * @param state The current state to be updated.
                 * @param block The message block to compress.
                 */
                void update(std::span<std::uint8_t> data)
                {
                    m_totalLen += data.size();
                    if(m_bufLen > 0)
                    {
                        const auto n = std::min(data.size(), BlockSize - m_bufLen); 
                        std::ranges::copy(data.first(n), m_buffer.data() + m_bufLen);
                        bufLen_ += n;
                        if(m_bufLen < BlockSize)
                        {
                            return;
                        }

                    }


                }
            
        };
    }

}

