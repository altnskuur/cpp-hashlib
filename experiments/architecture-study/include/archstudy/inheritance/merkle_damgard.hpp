/**
 * @file   merkle_damgard.hpp
 * @brief  Generic Merkle-Damgard hash construction.
 * @author Ugur Altinisik - altnskuur
 */

#pragma once
#include <algorithm>   ///< std::copy, std::min, std::ranges::copy
#include <array>
#include <bit>         ///< std::endian
#include <cstddef>     ///< std::size_t
#include <cstdint>     ///< std::uint8_t, std::uint32_t, std::uint64_t
#include <span>        ///< std::span
#include <vector>

/**
 * @brief Namespace for cryptographic hash functions.
 */
namespace crypto::hash 
{    
    inline constexpr std::size_t kBitsPerByte = 8; ///< Number of bits in one byte.

    /**
     * @brief Namespace for hash function constructions.
     */
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
         * Subclasses provide the IV, compress().
         *
         * @tparam WordType    Word type of the state (e.g. uint32_t for MD5).
         * @tparam StateWords  Number of words in the state (4 for MD5).
         * @tparam BlockSize   Message block size in bytes (64 for MD5).
         * @tparam Endianness  Byte order of the algorithm (std::endian::little for MD5).
         * @tparam LengthBytes Size of the length field in bytes (8 for MD5).
         */
        template <typename WordType, std::size_t StateWords, std::size_t BlockSize, std::endian Endianness, std::size_t LengthBytes = 8>
        class MerkleDamgard 
        {

            public:
                using State = std::array<WordType, StateWords>;     
                using Block = std::array<std::uint8_t, BlockSize>;

            private:
                static constexpr std::uint8_t  kPaddingMarker   = 0x80;                 ///< The '1' bit plus seven '0' bits, appended after the message.
                static constexpr std::size_t kLengthValueBytes = sizeof(std::uint64_t); ///< Bytes of the length value written into the padding.

                State m_iv;                     ///< Initialization vector
                State m_state;                  ///< Current state vector
                Block m_buffer{};               ///< Buffer for partial blocks
                std::size_t m_bufLen    = 0;    ///< Length of data in buffer
                std::uint64_t m_totalLen  = 0;  ///< Total length of the message

                /**
                 * @brief Pads the message to a multiple of the block size.
                 * @return A vector of blocks containing the padded message.
                 */
                std::vector<Block> padding() const
                {   
                    std::vector<Block> blocks(1);
                    std::copy(m_buffer.begin(), m_buffer.begin() + m_bufLen, blocks[0].begin());
                    std::size_t length = m_bufLen;

                    ///@note Append the '1' bit. in a byte demonstration '1000_0000'
                    blocks[0][length++] = kPaddingMarker; 
                    
                    if(length > BlockSize - LengthBytes)
                    {
                        blocks.emplace_back();
                    }

                    writeLength(blocks.back(), static_cast<std::uint64_t>(m_totalLen) * kBitsPerByte);
                    return blocks;
                }

                /**
                 * @brief Writes the length of the message in bits to the last bytes of the block.
                 * @param block The block to write the length to.
                 * @param bits  The length of the message in bits.
                 */
                void writeLength(Block& block, std::uint64_t bits) const
                {
                    std::size_t index = 0;
                    for(index = 0; index < kLengthValueBytes; ++index)
                    {
                        auto byte = static_cast<std::uint8_t>(bits >> (kBitsPerByte * index));
                        if constexpr (Endianness == std::endian::big)
                        {
                            block[BlockSize - 1 - index] = byte;
                        }
                        else 
                        {
                            block[BlockSize - LengthBytes + index] = byte;
                        }
                    }
                }

                /**
                 * @brief Converts a word to a byte array.
                 * @param word The word to convert.
                 * @return The resulting byte array.
                 */
                std::vector<std::uint8_t> wordsToBytes(const State& st) const
                {
                    std::vector<std::uint8_t> out;
                    out.reserve(digestSize());
                    for(WordType word : st)
                    {
                        for(std::size_t index = 0; index < sizeof(WordType); ++index)
                        {
                            std::size_t shift = 0;
                            if constexpr (Endianness == std::endian::big)
                            {
                                shift = kBitsPerByte * (sizeof(WordType) - index - 1);
                            }
                            else 
                            {
                                shift = kBitsPerByte * index;
                            }
                            out.push_back(static_cast<std::uint8_t>((word >> shift)));
                        }
                    }
                    out.resize(digestSize());
                    return out;
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

                /**
                 * @brief Returns the size of the digest in bytes.
                 * @return The size of the digest in bytes.
                 */
                virtual std::size_t digestSize() const 
                { 
                    return StateWords * sizeof(WordType); 
                }

                /**
                 * @brief Converts a byte array to a word of the appropriate type.
                 * @param bytes The byte array to convert.
                 * @return The converted word.
                 */
                static WordType bytesToWord(const std::uint8_t* p_bytes)
                {   
                    WordType bytes2Word = 0;
                    for(std::size_t index = 0; index < sizeof(WordType); ++index)
                    {
                        if constexpr (Endianness == std::endian::big)
                        {
                            shift = kBitsPerByte * (sizeof(WordType) - index - 1);
                        }
                        else 
                        {
                            shift = kBitsPerByte * index;
                        }
                        bytes2Word |= static_cast<WordType>(p_bytes[index]) << shift;
                    }
                    return bytes2Word;
                }
            public:
                /**
                 * @brief Virtual destructor for the Merkle-Damgard class.
                 */
                virtual ~MerkleDamgard() = default;

                /**
                 * @brief Updates the hash state with the given data.
                 * @param state The current state to be updated.
                 * @param block The message block to compress.
                 */
                void update(std::span<const std::uint8_t> data)
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
                        Block block;
                        std::ranges::copy(data.first(BlockSize), block.begin());
                        compress(m_state, block);
                        data = data.subspan(BlockSize);
                    }

                    /// @note #3 Keep the remaining bytes in the buffer
                    std::ranges::copy(data, m_buffer.data());
                    m_bufLen = data.size();
                }

                /**
                 * @brief Computes the final hash value.
                 * @return The computed hash value.
                 * @note After calling this function, the hash state is reset to its initial state.
                 */
                std::vector<std::uint8_t> digest()
                {
                    for(const Block& block : padding())
                    {
                        compress(m_state, block);
                    }
                    
                    auto out = wordsToBytes(m_state);
                    reset();
                    return out;
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

