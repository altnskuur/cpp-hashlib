/**
 * @file   merkle_damgard.hpp
 * @brief  Generic Merkle-Damgard hash construction and MD5.
 * @author Ugur Altinisik - altnskuur
 */

#pragma once
#include <array>
#include <vector>
#include <bit>

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
        template <typename WordType, std::size_t StateWords, std::size_t BlockSize, std::endian Endianness, std::size_t LengthBytes = 8>
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
                std::vector<Block> pad() const // ALTNSKUUR: EMPTY
                {

                }

                /**
                 * @brief Writes the length of the message in bits to the last bytes of the block.
                 * @param block The block to write the length to.
                 * @param length The length of the message in bits.
                 */
                void writeLength(Block& block, std::uint64_t length) const // ALTNSKUUR: EMPTY
                {

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

                    /// @note #1 If there is data in the buffer, fill it first
                    if(m_bufLen > 0)
                    {
                        const auto fillLen = std::min(data.size(), BlockSize - m_bufLen); 
                        std::ranges::copy(data.first(fillLen), m_buffer.data() + m_bufLen);
                        m_bufLen = m_bufLen + fillLen;
                        data = data.subspan(fillLen);

                        /// @note m_buffer is still not full, return
                        if(m_bufLen < BlockSize)
                        {
                            return; 
                        }

                        /// @note m_buffer is full, compress it and reset the buffer length
                        compress(m_state, m_buffer);
                        m_bufLen = 0;
                    }
                    
                    /// @note #2 Compress all full blocks in the input data
                    while(data.size() >= BlockSize)
                    {
                        compress(m_state, data.data());
                        data = data.subspan(BlockSize);
                    }

                    /// @note #3 Keep the remaining bytes in the buffer
                    std::ranges::copy(data, m_buffer.data());
                    m_bufLen = data.size();
                }

                /**
                 * @brief Computes the final hash value.
                 * @return The computed hash value.
                 */
                std::vector<std::uint8_t> digest const() // ALTNSKUUR: EMPTY
                {
                    
                }

                /**
                 * @brief Resets the hash function to its initial state.
                 */
                void reset()
                {
                    m_state = m_iv;
                    m_bufLen = 0;
                    m_totalLen = 0;

                }
            
        }; 
    } // namespace construction
} // namespace crypto::hash

