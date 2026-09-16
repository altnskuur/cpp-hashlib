# cpp-hashlib

A clean-architecture cryptographic hash library built from scratch using modern and low-level C++ standards.

## Documentation & Engineering Notes

To dive deeper into the implementation details and architectural choices:
* **[MD5 Deep Dive & Notes](https://app.notion.com/p/Message-Digest-Algorithm-MD5-3dd945c9dc4380a3b805c7c64821381c?source=copy_link):** Detailed breakdown of the MD5 algorithm stages, padding mechanics, and bit-level operations.
* **[Design Decisions](https://app.notion.com/p/Custom-MD5-Engine-Brute-Force-Puzzle-Solver-3d8945c9dc43803aa48ee49a23af7654?source=copy_link):** Engineering rationale behind data types (uint32_t, uint8_t), memory buffers, and std::span usage.