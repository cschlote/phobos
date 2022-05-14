/**
 * Computes xxHash hashes of arbitrary data. xxHash hashes are either uint32_t, uint64_t or uint128_t quantities that are like a
 * checksum or CRC, but are more robust and very performant.
 *
$(SCRIPT inhibitQuickIndex = 1;)

$(DIVC quickindex,
$(BOOKTABLE ,
$(TR $(TH Category) $(TH Functions)
)
$(TR $(TDNW Template API) $(TD $(MYREF XXHTemplate)
)
)
$(TR $(TDNW OOP API) $(TD $(MYREF XXH32Digest))
)
$(TR $(TDNW Helpers) $(TD $(MYREF xxh32Of))
)
)
)

 * This module conforms to the APIs defined in `std.digest`. To understand the
 * differences between the template and the OOP API, see $(MREF std, digest).
 *
 * This module publicly imports $(MREF std, digest) and can be used as a stand-alone
 * module.
 *
 * License:   $(HTTP www.boost.org/LICENSE_1_0.txt, Boost License 1.0).
 *
 * CTFE:
 * Digests do not work in CTFE
 *
 * Authors:
 * Carsten Schlote, Piotr Szturmaj, Kai Nacke, Johannes Pfau $(BR)
 * The routines and algorithms are provided by the xxhash.[ch] source
 * provided at $(I git@github.com:Cyan4973/xxHash.git).
 *
 * References:
 *      $(LINK2 https://github.com/Cyan4973/xxHash, GitHub website of project)
 *
 * Source: $(PHOBOSSRC std/digest/xxh.d)
 *
 */

/* xxh.d - A wrapper for the original C implementation */
module std.digest.xxh;

public import std.digest;

///
@safe unittest
{
    //Template API
    import std.digest.md;

    //Feeding data
    ubyte[1024] data;
    XXH_32 xxh;
    xxh.start();
    xxh.put(data[]);
    xxh.start(); //Start again
    xxh.put(data[]);
    auto hash = xxh.finish();
}

///
@safe unittest
{
    //OOP API
    import std.digest.md;

    auto xxh = new XXH32Digest();
    ubyte[] hash = xxh.digest("abc");
    assert(toHexString(hash) == "32D153FF", "Got " ~ toHexString(hash));

    //Feeding data
    ubyte[1024] data;
    xxh.put(data[]);
    xxh.reset(); //Start again
    xxh.put(data[]);
    hash = xxh.finish();
}

/* Port of C sources (release 0.8.1) to D language below */

enum XXH_NO_STREAM = false;
enum XXH_SIZE_OPT = 0;
enum XXH_FORCE_ALIGN_CHECK = true;
enum XXH32_ENDJMP = false;

version (LittleEndian)
    private immutable bool XXH_CPU_LITTLE_ENDIAN = true;
else
    private immutable bool XXH_CPU_LITTLE_ENDIAN = false;

alias xxh_u8 = ubyte;
alias xxh_u32 = uint;
alias xxh_u64 = ulong;

private uint32_t XXH_rotl32(uint32_t x, uint r) @trusted pure nothrow @nogc { return (((x) << (r)) | ((x) >> (32 - (r)))); }
private uint64_t XXH_rotl64(uint64_t x, uint r) @trusted pure nothrow @nogc { return (((x) << (r)) | ((x) >> (64 - (r)))); }
/* *************************************
*  Misc
***************************************/

enum XXH_VERSION_MAJOR   = 0;
enum XXH_VERSION_MINOR   = 8;
enum XXH_VERSION_RELEASE = 1;
/** Version number, encoded as two digits each */
enum XXH_VERSION_NUMBER = (XXH_VERSION_MAJOR *100*100 + XXH_VERSION_MINOR *100 + XXH_VERSION_RELEASE);

/** Get version number */
uint XXH_versionNumber ()  @trusted pure nothrow @nogc
{
    return XXH_VERSION_NUMBER;
}

private import std.stdint;
//private import std.int128;

alias XXH32_hash_t = uint32_t;
alias XXH64_hash_t = uint64_t;
struct XXH128_hash_t {
    XXH64_hash_t low64;   /*!< `value & 0xFFFFFFFFFFFFFFFF` */
    XXH64_hash_t high64;  /*!< `value >> 64` */
}

alias XXH64_canonical_t = uint64_t;
alias XXH128_canonical_t = XXH128_hash_t;

struct XXH3_state_t;


enum XXH_errorcode {
    XXH_OK = 0, /*!< OK */
    XXH_ERROR   /*!< Error */
}



/*!
 * @internal
 * @brief Structure for XXH32 streaming API.
 *
 * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
 * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined. Otherwise it is
 * an opaque type. This allows fields to safely be changed.
 *
 * Typedef'd to @ref XXH32_state_t.
 * Do not access the members of this struct directly.
 * @see XXH64_state_s, XXH3_state_s
 */
struct XXH32_state_t {
   XXH32_hash_t total_len_32; /*!< Total length hashed, modulo 2^32 */
   XXH32_hash_t large_len;    /*!< Whether the hash is >= 16 (handles @ref total_len_32 overflow) */
   XXH32_hash_t[4] v;         /*!< Accumulator lanes */
   XXH32_hash_t[4] mem32;     /*!< Internal buffer for partial reads. Treated as unsigned char[16]. */
   XXH32_hash_t memsize;      /*!< Amount of data in @ref mem32 */
   XXH32_hash_t reserved;     /*!< Reserved field. Do not read nor write to it. */
}   /* typedef'd to XXH32_state_t */

/*!
 * @internal
 * @brief Structure for XXH64 streaming API.
 *
 * @note This is only defined when @ref XXH_STATIC_LINKING_ONLY,
 * @ref XXH_INLINE_ALL, or @ref XXH_IMPLEMENTATION is defined. Otherwise it is
 * an opaque type. This allows fields to safely be changed.
 *
 * Typedef'd to @ref XXH64_state_t.
 * Do not access the members of this struct directly.
 * @see XXH32_state_s, XXH3_state_s
 */
struct XXH64_state_t {
   XXH64_hash_t total_len;    /*!< Total length hashed. This is always 64-bit. */
   XXH64_hash_t[4] v;         /*!< Accumulator lanes */
   XXH64_hash_t[4] mem64;     /*!< Internal buffer for partial reads. Treated as unsigned char[32]. */
   XXH32_hash_t memsize;      /*!< Amount of data in @ref mem64 */
   XXH32_hash_t reserved32;   /*!< Reserved field, needed for padding anyways*/
   XXH64_hash_t reserved64;   /*!< Reserved field. Do not read or write to it. */
}   /* typedef'd to XXH64_state_t */

struct XXH32_canonical_t {
    ubyte[4] digest; /*!< Hash bytes, big endian */
}

/** A 32-bit byteswap.
 *
 * Param: x = The 32-bit integer to byteswap.
 * Return: x, byteswapped.
 */
private xxh_u32 XXH_swap32 (xxh_u32 x) @trusted pure nothrow @nogc
{
    return  ((x << 24) & 0xff000000 ) |
            ((x <<  8) & 0x00ff0000 ) |
            ((x >>  8) & 0x0000ff00 ) |
            ((x >> 24) & 0x000000ff );
}

/* ***************************
*  Memory reads
*****************************/

/** Enum to indicate whether a pointer is aligned. */
enum XXH_alignment {
    XXH_aligned,  /** Aligned */
    XXH_unaligned /** Possibly unaligned */
}

private xxh_u32 XXH_read32(const void* ptr) @trusted pure nothrow @nogc
{
    xxh_u32 val;
    (cast(ubyte*) &val)[0 .. xxh_u32.sizeof] = (cast(ubyte*) ptr)[0 .. xxh_u32.sizeof];
    return val;
}

private xxh_u32 XXH_readLE32(const void* ptr) @trusted pure nothrow @nogc
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_read32(ptr) : XXH_swap32(XXH_read32(ptr));
}

private xxh_u32 XXH_readBE32(const void* ptr) @trusted pure nothrow @nogc
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_swap32(XXH_read32(ptr)) : XXH_read32(ptr);
}

private xxh_u32 XXH_readLE32_align(const void* ptr, XXH_alignment align_) @trusted pure nothrow @nogc
{
    if (align_==XXH_alignment.XXH_unaligned) {
        return XXH_readLE32(ptr);
    } else {
        return XXH_CPU_LITTLE_ENDIAN ? * cast(const xxh_u32*) ptr : XXH_swap32(* cast(const xxh_u32*) ptr);
    }
}

/* *******************************************************************
*  32-bit hash functions
*********************************************************************/
enum XXH_PRIME32_1 = 0x9E3779B1U;  /** 0b10011110001101110111100110110001 */
enum XXH_PRIME32_2 = 0x85EBCA77U;  /** 0b10000101111010111100101001110111 */
enum XXH_PRIME32_3 = 0xC2B2AE3DU;  /** 0b11000010101100101010111000111101 */
enum XXH_PRIME32_4 = 0x27D4EB2FU;  /** 0b00100111110101001110101100101111 */
enum XXH_PRIME32_5 = 0x165667B1U;  /** 0b00010110010101100110011110110001 */

/**  Normal stripe processing routine.
 *
 * This shuffles the bits so that any bit from @p input impacts several bits in
 * acc.
 *
 * Param: acc The accumulator lane.
 * Param: input The stripe of input to mix.
 * Return: The mixed accumulator lane.
 */
private xxh_u32 XXH32_round(xxh_u32 acc, xxh_u32 input) @trusted pure nothrow @nogc
{
    acc += input * XXH_PRIME32_2;
    acc  = XXH_rotl32(acc, 13);
    acc *= XXH_PRIME32_1;
    return acc;
}

/** Mixes all bits to finalize the hash.
 *
 * The final mix ensures that all input bits have a chance to impact any bit in
 * the output digest, resulting in an unbiased distribution.
 *
 * Param: hash = The hash to avalanche.
 * Return The avalanched hash.
 */
private xxh_u32 XXH32_avalanche(xxh_u32 hash) @trusted pure nothrow @nogc
{
    hash ^= hash >> 15;
    hash *= XXH_PRIME32_2;
    hash ^= hash >> 13;
    hash *= XXH_PRIME32_3;
    hash ^= hash >> 16;
    return hash;
}

private xxh_u32 XXH_get32bits(const void* p, XXH_alignment align_) @trusted pure nothrow @nogc
{
    return XXH_readLE32_align(p, align_);
}

/*!
 * @internal
 * @brief Processes the last 0-15 bytes of @p ptr.
 *
 * There may be up to 15 bytes remaining to consume from the input.
 * This final stage will digest them to ensure that all input bytes are present
 * in the final mix.
 *
 * @param hash The hash to finalize.
 * @param ptr The pointer to the remaining input.
 * @param len The remaining length, modulo 16.
 * @param align Whether @p ptr is aligned.
 * @return The finalized hash.
 * @see XXH64_finalize().
 */
private xxh_u32
XXH32_finalize(xxh_u32 hash, const(xxh_u8)* ptr, size_t len, XXH_alignment align_)  @trusted pure nothrow @nogc
{
    void XXH_PROCESS1(ref uint32_t hash, ref const(xxh_u8)* ptr)
    {
        hash += (*ptr++) * XXH_PRIME32_5;
        hash = XXH_rotl32(hash, 11) * XXH_PRIME32_1;
    }
    void XXH_PROCESS4(ref uint32_t hash, ref const(xxh_u8)* ptr)
    {
        hash += XXH_get32bits(ptr, align_) * XXH_PRIME32_3;
        ptr += 4;
        hash  = XXH_rotl32(hash, 17) * XXH_PRIME32_4;
    }

    /* Compact rerolled version; generally faster */
    if (!XXH32_ENDJMP) {
        len &= 15;
        while (len >= 4) {
            XXH_PROCESS4(hash, ptr);
            len -= 4;
        }
        while (len > 0) {
            XXH_PROCESS1(hash, ptr);
            --len;
        }
        return XXH32_avalanche(hash);
    } else {
         switch(len&15) /* or switch(bEnd - p) */ {
           case 12:      XXH_PROCESS4(hash, ptr);
                         goto case;
           case 8:       XXH_PROCESS4(hash, ptr);
                         goto case;
           case 4:       XXH_PROCESS4(hash, ptr);
                         return XXH32_avalanche(hash);

           case 13:      XXH_PROCESS4(hash, ptr);
                         goto case;
           case 9:       XXH_PROCESS4(hash, ptr);
                         goto case;
           case 5:       XXH_PROCESS4(hash, ptr);
                         XXH_PROCESS1(hash, ptr);
                         return XXH32_avalanche(hash);

           case 14:      XXH_PROCESS4(hash, ptr);
                         goto case;
           case 10:      XXH_PROCESS4(hash, ptr);
                         goto case;
           case 6:       XXH_PROCESS4(hash, ptr);
                         XXH_PROCESS1(hash, ptr);
                         XXH_PROCESS1(hash, ptr);
                         return XXH32_avalanche(hash);

           case 15:      XXH_PROCESS4(hash, ptr);
                         goto case;
           case 11:      XXH_PROCESS4(hash, ptr);
                         goto case;
           case 7:       XXH_PROCESS4(hash, ptr);
                         goto case;
           case 3:       XXH_PROCESS1(hash, ptr);
                         goto case;
           case 2:       XXH_PROCESS1(hash, ptr);
                         goto case;
           case 1:       XXH_PROCESS1(hash, ptr);
                         goto case;
           case 0:       return XXH32_avalanche(hash);
           default: assert(0);
        }
        return hash;   /* reaching this point is deemed impossible */
    }
}

/** The implementation for @ref XXH32().
 *
 * Params:
 *  input = Directly passed from @ref XXH32().
 *  len = Ditto
 *  seed = Ditto
 *  align_ = Whether input is aligned.
 * Return: The calculated hash.
 */
private xxh_u32
XXH32_endian_align(const(xxh_u8)* input, size_t len, xxh_u32 seed, XXH_alignment align_) @trusted pure nothrow @nogc
{
    xxh_u32 h32;

    if (len>=16) {
        const xxh_u8* bEnd = input + len;
        const xxh_u8* limit = bEnd - 15;
        xxh_u32 v1 = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
        xxh_u32 v2 = seed + XXH_PRIME32_2;
        xxh_u32 v3 = seed + 0;
        xxh_u32 v4 = seed - XXH_PRIME32_1;

        do {
            v1 = XXH32_round(v1, XXH_get32bits(input, align_)); input += 4;
            v2 = XXH32_round(v2, XXH_get32bits(input, align_)); input += 4;
            v3 = XXH32_round(v3, XXH_get32bits(input, align_)); input += 4;
            v4 = XXH32_round(v4, XXH_get32bits(input, align_)); input += 4;
        } while (input < limit);

        h32 = XXH_rotl32(v1, 1)  + XXH_rotl32(v2, 7)
            + XXH_rotl32(v3, 12) + XXH_rotl32(v4, 18);
    } else {
        h32  = seed + XXH_PRIME32_5;
    }

    h32 += cast(xxh_u32) len;

    return XXH32_finalize(h32, input, len&15, align_);
}

XXH32_hash_t XXH32 (const void* input, size_t len, XXH32_hash_t seed) @trusted pure nothrow @nogc
{
    static if (!XXH_NO_STREAM && XXH_SIZE_OPT >= 2) {
        /* Simple version, good for code maintenance, but unfortunately slow for small inputs */
        XXH32_state_t state;
        XXH32_reset(&state, seed);
        XXH32_update(&state, cast(const(xxh_u8)*) input, len);
        return XXH32_digest(&state);
    } else {
        if (XXH_FORCE_ALIGN_CHECK) {
            if (((cast(size_t) input) & 3) == 0) {   /* Input is 4-bytes aligned, leverage the speed benefit */
                return XXH32_endian_align(cast(const(xxh_u8)*)input, len, seed, XXH_alignment.XXH_aligned);
        }   }

        return XXH32_endian_align(cast(const(xxh_u8)*) input, len, seed, XXH_alignment.XXH_unaligned);
    }
}

XXH32_state_t* XXH32_createState() @trusted pure nothrow @nogc
{
    import core.memory : pureMalloc;
    return cast(XXH32_state_t*) pureMalloc(XXH32_state_t.sizeof);

}
XXH_errorcode XXH32_freeState(XXH32_state_t* statePtr) @trusted pure nothrow @nogc
{
    import core.memory : pureFree;

    pureFree(statePtr);
    return XXH_errorcode.XXH_OK;
}

void XXH32_copyState(XXH32_state_t* dstState, const XXH32_state_t* srcState) @trusted pure nothrow @nogc
{
    import core.stdc.string : memcpy;

    memcpy(dstState, srcState, (*dstState).sizeof);
}

XXH_errorcode XXH32_reset(XXH32_state_t* statePtr, XXH32_hash_t seed) @trusted pure nothrow @nogc
{
    import core.stdc.string : memset;

    assert(statePtr != null);
    memset(statePtr, 0, (*statePtr).sizeof);
    statePtr.v[0] = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
    statePtr.v[1] = seed + XXH_PRIME32_2;
    statePtr.v[2] = seed + 0;
    statePtr.v[3] = seed - XXH_PRIME32_1;
    return XXH_errorcode.XXH_OK;
}

XXH_errorcode XXH32_update(XXH32_state_t* state, const void* input, size_t len) @trusted pure nothrow @nogc
{
    import core.stdc.string : memcpy;

    if (input==null) {
        assert(len == 0);
        return XXH_errorcode.XXH_OK;
    }

    {   const(xxh_u8)* p = cast(const(xxh_u8) *) input;
        const xxh_u8* bEnd = p + len;

        state.total_len_32 += cast(XXH32_hash_t) len;
        state.large_len |= cast(XXH32_hash_t) ((len>=16) | (state.total_len_32>=16));

        if (state.memsize + len < 16)  {   /* fill in tmp buffer */
            memcpy(cast(xxh_u8*) (state.mem32) + state.memsize, input, len);
            state.memsize += cast(XXH32_hash_t) len;
            return XXH_errorcode.XXH_OK;
        }

        if (state.memsize) {   /* some data left from previous update */
            memcpy(cast(xxh_u8*) (state.mem32) + state.memsize, input, 16-state.memsize);
            {
                const(xxh_u32)* p32 = cast(const(xxh_u32)*) &state.mem32[0];
                state.v[0] = XXH32_round(state.v[0], XXH_readLE32(p32)); p32++;
                state.v[1] = XXH32_round(state.v[1], XXH_readLE32(p32)); p32++;
                state.v[2] = XXH32_round(state.v[2], XXH_readLE32(p32)); p32++;
                state.v[3] = XXH32_round(state.v[3], XXH_readLE32(p32));
            }
            p += 16-state.memsize;
            state.memsize = 0;
        }

        if (p <= bEnd-16) {
            const xxh_u8* limit = bEnd - 16;

            do {
                state.v[0] = XXH32_round(state.v[0], XXH_readLE32(p)); p+=4;
                state.v[1] = XXH32_round(state.v[1], XXH_readLE32(p)); p+=4;
                state.v[2] = XXH32_round(state.v[2], XXH_readLE32(p)); p+=4;
                state.v[3] = XXH32_round(state.v[3], XXH_readLE32(p)); p+=4;
            } while (p<=limit);

        }

        if (p < bEnd) {
            memcpy(cast(void*) &state.mem32[0], p, cast(size_t) (bEnd-p));
            state.memsize = cast(XXH32_hash_t) (bEnd-p);
        }
    }

    return XXH_errorcode.XXH_OK;
}

XXH32_hash_t XXH32_digest(const XXH32_state_t* state) @trusted pure nothrow @nogc
{
    xxh_u32 h32;

    if (state.large_len) {
        h32 = XXH_rotl32(state.v[0], 1)
            + XXH_rotl32(state.v[1], 7)
            + XXH_rotl32(state.v[2], 12)
            + XXH_rotl32(state.v[3], 18);
    } else {
        h32 = state.v[2] /* == seed */ + XXH_PRIME32_5;
    }

    h32 += state.total_len_32;

    return XXH32_finalize(h32, cast(const xxh_u8*) state.mem32, state.memsize, XXH_alignment.XXH_aligned);
}

void XXH32_canonicalFromHash(XXH32_canonical_t* dst, XXH32_hash_t hash) @trusted pure nothrow @nogc
{
    import core.stdc.string : memcpy;

    static assert((XXH32_canonical_t).sizeof == (XXH32_hash_t).sizeof);
    static if (XXH_CPU_LITTLE_ENDIAN) hash = XXH_swap32(hash);
    memcpy(dst, &hash, (*dst).sizeof);
}

XXH32_hash_t XXH32_hashFromCanonical(const XXH32_canonical_t* src) @trusted pure nothrow @nogc
{
    return XXH_readBE32(src);
}

/* ----------------------------------------------------------------------------------------*/
/* ----------------------------------------------------------------------------------------*/
/* ----------------------------------------------------------------------------------------*/

private xxh_u64 XXH_read64(const void* ptr) @trusted pure nothrow @nogc
{
    xxh_u64 val;
    (cast(ubyte*) &val)[0 .. xxh_u64.sizeof] = (cast(ubyte*) ptr)[0 .. xxh_u64.sizeof];
    return val;
}

private xxh_u64 XXH_swap64(xxh_u64 x) @trusted pure nothrow @nogc
{
    return  ((x << 56) & 0xff00000000000000) |
            ((x << 40) & 0x00ff000000000000) |
            ((x << 24) & 0x0000ff0000000000) |
            ((x << 8)  & 0x000000ff00000000) |
            ((x >> 8)  & 0x00000000ff000000) |
            ((x >> 24) & 0x0000000000ff0000) |
            ((x >> 40) & 0x000000000000ff00) |
            ((x >> 56) & 0x00000000000000ff);
}

private xxh_u64 XXH_readLE64(const void* ptr) @trusted pure nothrow @nogc
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_read64(ptr) : XXH_swap64(XXH_read64(ptr));
}

private xxh_u64 XXH_readBE64(const void* ptr) @trusted pure nothrow @nogc
{
    return XXH_CPU_LITTLE_ENDIAN ? XXH_swap64(XXH_read64(ptr)) : XXH_read64(ptr);
}

private xxh_u64 XXH_readLE64_align(const void* ptr, XXH_alignment align_) @trusted pure nothrow @nogc
{
    if (align_==XXH_alignment.XXH_unaligned) {
        return XXH_readLE64(ptr);
    } else {
        return XXH_CPU_LITTLE_ENDIAN ? * cast(const xxh_u64*) ptr : XXH_swap64(* cast(const xxh_u64*) ptr);
    }
}

enum XXH_PRIME64_1 = 0x9E3779B185EBCA87;  /*!< 0b1001111000110111011110011011000110000101111010111100101010000111 */
enum XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4F;  /*!< 0b1100001010110010101011100011110100100111110101001110101101001111 */
enum XXH_PRIME64_3 = 0x165667B19E3779F9;  /*!< 0b0001011001010110011001111011000110011110001101110111100111111001 */
enum XXH_PRIME64_4 = 0x85EBCA77C2B2AE63;  /*!< 0b1000010111101011110010100111011111000010101100101010111001100011 */
enum XXH_PRIME64_5 = 0x27D4EB2F165667C5;  /*!< 0b0010011111010100111010110010111100010110010101100110011111000101 */

private xxh_u64 XXH64_round(xxh_u64 acc, xxh_u64 input) @trusted pure nothrow @nogc
{
    acc += input * XXH_PRIME64_2;
    acc  = XXH_rotl64(acc, 31);
    acc *= XXH_PRIME64_1;
    return acc;
}

private xxh_u64 XXH64_mergeRound(xxh_u64 acc, xxh_u64 val) @trusted pure nothrow @nogc
{
    val  = XXH64_round(0, val);
    acc ^= val;
    acc  = acc * XXH_PRIME64_1 + XXH_PRIME64_4;
    return acc;
}

private xxh_u64 XXH64_avalanche(xxh_u64 hash) @trusted pure nothrow @nogc
{
    hash ^= hash >> 33;
    hash *= XXH_PRIME64_2;
    hash ^= hash >> 29;
    hash *= XXH_PRIME64_3;
    hash ^= hash >> 32;
    return hash;
}

xxh_u64 XXH_get64bits(const void* p, XXH_alignment align_) @trusted pure nothrow @nogc
{
    return XXH_readLE64_align(p, align_);
}

/*!
 * @internal
 * @brief Processes the last 0-31 bytes of @p ptr.
 *
 * There may be up to 31 bytes remaining to consume from the input.
 * This final stage will digest them to ensure that all input bytes are present
 * in the final mix.
 *
 * @param hash The hash to finalize.
 * @param ptr The pointer to the remaining input.
 * @param len The remaining length, modulo 32.
 * @param align Whether @p ptr is aligned.
 * @return The finalized hash
 * @see XXH32_finalize().
 */
private xxh_u64
XXH64_finalize(xxh_u64 hash, const(xxh_u8)* ptr, size_t len, XXH_alignment align_) @trusted pure nothrow @nogc
{
    if (ptr==null) assert (len == 0);

    len &= 31;
    while (len >= 8) {
        xxh_u64 k1 = XXH64_round(0, XXH_get64bits(ptr, align_));
        ptr += 8;
        hash ^= k1;
        hash  = XXH_rotl64(hash,27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        len -= 8;
    }
    if (len >= 4) {
        hash ^= cast(xxh_u64) (XXH_get32bits(ptr, align_)) * XXH_PRIME64_1;
        ptr += 4;
        hash = XXH_rotl64(hash, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        len -= 4;
    }
    while (len > 0) {
        hash ^= (*ptr++) * XXH_PRIME64_5;
        hash = XXH_rotl64(hash, 11) * XXH_PRIME64_1;
        --len;
    }
    return  XXH64_avalanche(hash);
}

/*!
 * @internal
 * @brief The implementation for @ref XXH64().
 *
 * @param input , len , seed Directly passed from @ref XXH64().
 * @param align Whether @p input is aligned.
 * @return The calculated hash.
 */
private xxh_u64
XXH64_endian_align(const(xxh_u8)* input, size_t len, xxh_u64 seed, XXH_alignment align_) @trusted pure nothrow @nogc
{
    xxh_u64 h64;
    if (input==null) assert(len == 0);

    if (len>=32) {
        const xxh_u8* bEnd = input + len;
        const xxh_u8* limit = bEnd - 31;
        xxh_u64 v1 = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
        xxh_u64 v2 = seed + XXH_PRIME64_2;
        xxh_u64 v3 = seed + 0;
        xxh_u64 v4 = seed - XXH_PRIME64_1;

        do {
            v1 = XXH64_round(v1, XXH_get64bits(input, align_)); input+=8;
            v2 = XXH64_round(v2, XXH_get64bits(input, align_)); input+=8;
            v3 = XXH64_round(v3, XXH_get64bits(input, align_)); input+=8;
            v4 = XXH64_round(v4, XXH_get64bits(input, align_)); input+=8;
        } while (input<limit);

        h64 = XXH_rotl64(v1, 1) + XXH_rotl64(v2, 7) + XXH_rotl64(v3, 12) + XXH_rotl64(v4, 18);
        h64 = XXH64_mergeRound(h64, v1);
        h64 = XXH64_mergeRound(h64, v2);
        h64 = XXH64_mergeRound(h64, v3);
        h64 = XXH64_mergeRound(h64, v4);

    } else {
        h64  = seed + XXH_PRIME64_5;
    }

    h64 += cast(xxh_u64) len;

    return XXH64_finalize(h64, input, len, align_);
}

XXH64_hash_t XXH64 (const void* input, size_t len, XXH64_hash_t seed) @trusted pure nothrow @nogc
{
    static if (!XXH_NO_STREAM && XXH_SIZE_OPT >= 2) {
        /* Simple version, good for code maintenance, but unfortunately slow for small inputs */
        XXH64_state_t state;
        XXH64_reset(&state, seed);
        XXH64_update(&state, cast(const(xxh_u8)*) input, len);
        return XXH64_digest(&state);
    } else {
        if (XXH_FORCE_ALIGN_CHECK) {
            if (((cast(size_t) input) & 7)==0) {  /* Input is aligned, let's leverage the speed advantage */
                return XXH64_endian_align(cast(const(xxh_u8)*) input, len, seed,  XXH_alignment.XXH_aligned);
        }   }

        return XXH64_endian_align(cast(const(xxh_u8)*) input, len, seed,  XXH_alignment.XXH_unaligned);
    }
}

XXH64_state_t* XXH64_createState() @trusted pure nothrow @nogc
{
    import core.memory : pureMalloc;
    return cast(XXH64_state_t*) pureMalloc(XXH64_state_t.sizeof);

}
XXH_errorcode XXH64_freeState(XXH64_state_t* statePtr) @trusted pure nothrow @nogc
{
    import core.memory : pureFree;

    pureFree(statePtr);
    return XXH_errorcode.XXH_OK;
}

void XXH64_copyState(XXH64_state_t* dstState, const XXH64_state_t* srcState) @trusted pure nothrow @nogc
{
    import core.stdc.string : memcpy;

    memcpy(dstState, srcState, (*dstState).sizeof);
}

XXH_errorcode XXH64_reset(XXH64_state_t* statePtr, XXH64_hash_t seed) @trusted pure nothrow @nogc
{
    import core.stdc.string : memset;

    assert(statePtr != null);
    memset(statePtr, 0, (*statePtr).sizeof);
    statePtr.v[0] = seed + XXH_PRIME64_1 + XXH_PRIME64_2;
    statePtr.v[1] = seed + XXH_PRIME64_2;
    statePtr.v[2] = seed + 0;
    statePtr.v[3] = seed - XXH_PRIME64_1;
    return XXH_errorcode.XXH_OK;
}

XXH_errorcode XXH64_update (XXH64_state_t* state, const void* input, size_t len) @trusted pure nothrow @nogc
{
    import core.stdc.string : memcpy;

    if (input==null) {
        assert(len == 0);
        return XXH_errorcode.XXH_OK;
    }

    {   const(xxh_u8)* p = cast(const(xxh_u8) *)input;
        const xxh_u8* bEnd = p + len;

        state.total_len += len;

        if (state.memsize + len < 32) {  /* fill in tmp buffer */
            memcpy((cast(xxh_u8*) state.mem64) + state.memsize, input, len);
            state.memsize += cast(xxh_u32) len;
            return XXH_errorcode.XXH_OK;
        }

        if (state.memsize) {   /* tmp buffer is full */
            memcpy((cast(xxh_u8*) state.mem64) + state.memsize, input, 32-state.memsize);
            state.v[0] = XXH64_round(state.v[0], XXH_readLE64(&state.mem64[0]));
            state.v[1] = XXH64_round(state.v[1], XXH_readLE64(&state.mem64[1]));
            state.v[2] = XXH64_round(state.v[2], XXH_readLE64(&state.mem64[2]));
            state.v[3] = XXH64_round(state.v[3], XXH_readLE64(&state.mem64[3]));
            p += 32 - state.memsize;
            state.memsize = 0;
        }

        if (p+32 <= bEnd) {
            const xxh_u8* limit = bEnd - 32;

            do {
                state.v[0] = XXH64_round(state.v[0], XXH_readLE64(p)); p+=8;
                state.v[1] = XXH64_round(state.v[1], XXH_readLE64(p)); p+=8;
                state.v[2] = XXH64_round(state.v[2], XXH_readLE64(p)); p+=8;
                state.v[3] = XXH64_round(state.v[3], XXH_readLE64(p)); p+=8;
            } while (p<=limit);

        }

        if (p < bEnd) {
            memcpy(cast(void*) &state.mem64[0], p, cast(size_t) (bEnd-p));
            state.memsize = cast(XXH32_hash_t)(bEnd-p);
        }
    }

    return XXH_errorcode.XXH_OK;
}

XXH64_hash_t XXH64_digest(const XXH64_state_t* state) @trusted pure nothrow @nogc
{
    xxh_u64 h64;

    if (state.total_len >= 32) {
        h64 = XXH_rotl64(state.v[0], 1) + XXH_rotl64(state.v[1], 7) + XXH_rotl64(state.v[2], 12) + XXH_rotl64(state.v[3], 18);
        h64 = XXH64_mergeRound(h64, state.v[0]);
        h64 = XXH64_mergeRound(h64, state.v[1]);
        h64 = XXH64_mergeRound(h64, state.v[2]);
        h64 = XXH64_mergeRound(h64, state.v[3]);
    } else {
        h64  = state.v[2] /*seed*/ + XXH_PRIME64_5;
    }

    h64 += cast(xxh_u64) state.total_len;

    return XXH64_finalize(h64, cast(const xxh_u8*) state.mem64, cast(size_t) state.total_len, XXH_alignment.XXH_aligned);
}

void XXH64_canonicalFromHash(XXH64_canonical_t* dst, XXH64_hash_t hash)
{
    import core.stdc.string : memcpy;

    static assert((XXH64_canonical_t).sizeof == (XXH64_hash_t).sizeof);
    if (XXH_CPU_LITTLE_ENDIAN) hash = XXH_swap64(hash);
    memcpy(dst, &hash, (*dst).sizeof);
}

/*! @ingroup XXH64_family */
XXH64_hash_t XXH64_hashFromCanonical(const XXH64_canonical_t* src)
{
    return XXH_readBE64(src);
}

/* ----------------------------------------------------------------------------------------*/
/* ----------------------------------------------------------------------------------------*/
extern (C) {
//    uint XXH_versionNumber () @trusted pure nothrow @nogc;
//    XXH32_hash_t XXH32 (const void* input, size_t length, XXH32_hash_t seed) @trusted pure nothrow @nogc;
//    XXH32_state_t* XXH32_createState() @trusted pure nothrow @nogc;
//    XXH_errorcode  XXH32_freeState(XXH32_state_t* statePtr) @trusted pure nothrow @nogc;
//    void XXH32_copyState(XXH32_state_t* dst_state, const XXH32_state_t* src_state) @trusted pure nothrow @nogc;
//    XXH_errorcode XXH32_reset  (XXH32_state_t* statePtr, XXH32_hash_t seed) @trusted pure nothrow @nogc;
//    XXH_errorcode XXH32_update (XXH32_state_t* statePtr, const void* input, size_t length) @trusted pure nothrow @nogc;
//    XXH32_hash_t XXH32_digest (const XXH32_state_t* statePtr) @trusted pure nothrow @nogc;
//    void XXH32_canonicalFromHash(XXH32_canonical_t* dst, XXH32_hash_t hash) @trusted pure nothrow @nogc;
//    XXH32_hash_t XXH32_hashFromCanonical(const XXH32_canonical_t* src) @trusted pure nothrow @nogc;

//    XXH64_hash_t XXH64(const void* input, size_t length, XXH64_hash_t seed) @trusted pure nothrow @nogc;
//    XXH64_state_t* XXH64_createState() @trusted pure nothrow @nogc;
//    XXH_errorcode  XXH64_freeState(XXH64_state_t* statePtr) @trusted pure nothrow @nogc;
//    void XXH64_copyState(XXH64_state_t* dst_state, const XXH64_state_t* src_state) @trusted pure nothrow @nogc;
//    XXH_errorcode XXH64_reset  (XXH64_state_t* statePtr, XXH64_hash_t seed) @trusted pure nothrow @nogc;
//    XXH_errorcode XXH64_update (XXH64_state_t* statePtr, const void* input, size_t length) @trusted pure nothrow @nogc;
//    XXH64_hash_t XXH64_digest (const XXH64_state_t* statePtr) @trusted pure nothrow @nogc;
//    void XXH64_canonicalFromHash(XXH64_canonical_t* dst, XXH64_hash_t hash) @trusted pure nothrow @nogc;
//    XXH64_hash_t XXH64_hashFromCanonical(const XXH64_canonical_t* src) @trusted pure nothrow @nogc;

    XXH64_hash_t XXH3_64bits(const void* input, size_t length) @trusted pure nothrow @nogc;
    XXH64_hash_t XXH3_64bits_withSeed(const void* input, size_t length, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH64_hash_t XXH3_64bits_withSecret(const void* data, size_t len, const void* secret, size_t secretSize)
        @trusted pure nothrow @nogc;
    XXH3_state_t* XXH3_createState() @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_freeState(XXH3_state_t* statePtr) @trusted pure nothrow @nogc;
    void XXH3_copyState(XXH3_state_t* dst_state, const XXH3_state_t* src_state) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_reset(XXH3_state_t* statePtr) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_reset_withSeed(XXH3_state_t* statePtr, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_reset_withSecret(XXH3_state_t* statePtr, const void* secret, size_t secretSize)
        @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_update (XXH3_state_t* statePtr, const void* input, size_t length)
        @trusted pure nothrow @nogc;
    XXH64_hash_t  XXH3_64bits_digest (const XXH3_state_t* statePtr) @trusted pure nothrow @nogc;

    XXH128_hash_t XXH3_128bits(const void* data, size_t len) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSeed(const void* data, size_t len, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSecret(const void* data, size_t len, const void* secret, size_t secretSize)
        @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_reset(XXH3_state_t* statePtr) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_reset_withSeed(XXH3_state_t* statePtr, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_reset_withSecret(XXH3_state_t* statePtr, const void* secret, size_t secretSize)
        @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_update (XXH3_state_t* statePtr, const void* input, size_t length)
        @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_digest (const XXH3_state_t* statePtr) @trusted pure nothrow @nogc;

    int XXH128_isEqual(XXH128_hash_t h1, XXH128_hash_t h2) @trusted pure nothrow @nogc;
    int XXH128_cmp(const void* h128_1, const void* h128_2) @trusted pure nothrow @nogc;
    void XXH128_canonicalFromHash(XXH128_canonical_t* dst, XXH128_hash_t hash) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH128_hashFromCanonical(const XXH128_canonical_t* src) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH128(const void* data, size_t len, XXH64_hash_t seed) @trusted pure nothrow @nogc;

    XXH_errorcode XXH3_generateSecret(void* secretBuffer, size_t secretSize, const void* customSeed,
        size_t customSeedSize) @trusted pure nothrow @nogc;
    void XXH3_generateSecret_fromSeed(void* secretBuffer, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH64_hash_t  XXH3_64bits_dispatch(const void* input, size_t len) @trusted pure nothrow @nogc;
    XXH64_hash_t  XXH3_64bits_withSeed_dispatch(const void* input, size_t len, XXH64_hash_t seed)
        @trusted pure nothrow @nogc;
    XXH64_hash_t  XXH3_64bits_withSecret_dispatch(const void* input, size_t len, const void* secret,
        size_t secretLen) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_update_dispatch(XXH3_state_t* state, const void* input, size_t len)
        @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_dispatch(const void* input, size_t len) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSeed_dispatch(const void* input, size_t len, XXH64_hash_t seed)
        @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSecret_dispatch(const void* input, size_t len, const void* secret,
        size_t secretLen) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_update_dispatch(XXH3_state_t* state, const void* input, size_t len)
        @trusted pure nothrow @nogc;
}

import core.bitop;

public import std.digest;

/*
 * Helper methods for encoding the buffer.
 * Can be removed if the optimizer can inline the methods from std.bitmanip.
 */
version (LittleEndian)
{
    private alias nativeToBigEndian = bswap;
    private alias bigEndianToNative = bswap;
}
else pragma(inline, true) private pure @nogc nothrow @safe
{
    uint nativeToBigEndian(uint val) { return val; }
    ulong nativeToBigEndian(ulong val) { return val; }
    alias bigEndianToNative = nativeToBigEndian;
}

/**
 * Template API XXHTemplate implementation. Uses parameters to configure for number of bits and XXH variant (classic or XXH3)
 * See `std.digest` for differences between template and OOP API.
 */
struct XXHTemplate(HASH, STATE, bool useXXH3)
{
    private:
        HASH hash;
        STATE* state = null;
        HASH seed = HASH.init;

    public:
        enum digestSize = HASH.sizeof * 8;

        /**
         * Use this to feed the digest with data.
         * Also implements the $(REF isOutputRange, std,range,primitives)
         * interface for `ubyte` and `const(ubyte)[]`.
         *
         * Example:
         * ----
         * XXHTemplate!(hashtype,statetype,useXXH3) dig;
         * dig.put(cast(ubyte) 0); //single ubyte
         * dig.put(cast(ubyte) 0, cast(ubyte) 0); //variadic
         * ubyte[10] buf;
         * dig.put(buf); //buffer
         * ----
         */
        void put(scope const(ubyte)[] data...) @trusted pure nothrow @nogc
        {
            XXH_errorcode ec;
            if (state == null) this.start;
            static if (digestSize == 32)
                ec = XXH32_update(state, data.ptr, data.length);
            else static if (digestSize == 64 && !useXXH3)
                ec = XXH64_update(state, data.ptr, data.length);
            else static if (digestSize == 64 && useXXH3)
                ec = XXH3_64bits_update(state, data.ptr, data.length);
            else static if (digestSize == 128)
                ec = XXH3_128bits_update(state, data.ptr, data.length);
            else
                assert(false, "Unknown XXH bitdeep or variant");
            assert(ec == XXH_errorcode.XXH_OK, "Update failed");
        }

        /**
         * Used to (re)initialize the XXHTemplate digest.
         *
         * Example:
         * --------
         * XXHTemplate!(hashtype,statetype,useXXH3) digest;
         * digest.start();
         * digest.put(0);
         * --------
         */
        void start() @safe pure nothrow @nogc
        {
            this = typeof(this).init;
            XXH_errorcode ec;
            static if (digestSize == 32)
            {
                if (state == null) state = XXH32_createState();
                ec = XXH32_reset(state, seed);
            }
            else static if (digestSize == 64 && !useXXH3)
            {
                if (state == null) state = XXH64_createState();
                ec = XXH64_reset(state, seed);
            }
            else static if (digestSize == 64 && useXXH3)
            {
                if (state == null) state = XXH3_createState();
                ec = XXH3_64bits_reset(state);
            }
            else static if (digestSize == 128)
            {
                if (state == null) state = XXH3_createState();
                ec = XXH3_128bits_reset(state);
            }
            else
                assert(false, "Unknown XXH bitdeep or variant");
            //assert(ec == XXH_errorcode.XXH_OK, "reset failed");
        }

        /**
         * Returns the finished XXH hash. This also calls $(LREF start) to
         * reset the internal state.
          */
        ubyte[digestSize/8] finish() @trusted pure nothrow @nogc
        {
            XXH_errorcode ec;
            static if (digestSize == 32)
            {
                hash = XXH32_digest(state);
                if (state != null) ec = XXH32_freeState(state);
                auto rc = nativeToBigEndian(hash);
            }
            else static if (digestSize == 64 && !useXXH3)
            {
                hash = XXH64_digest(state);
                if (state != null) ec = XXH64_freeState(state);
                auto rc = nativeToBigEndian(hash);
            }
            else static if (digestSize == 64 && useXXH3)
            {
                hash = XXH3_64bits_digest(state);
                if (state != null) ec = XXH3_freeState(state);
                auto rc = nativeToBigEndian(hash);
            }
            else static if (digestSize == 128)
            {
                hash = XXH3_128bits_digest(state);
                if (state != null) ec = XXH3_freeState(state);
                HASH rc;
                // Note: low64 and high64 are intentionally exchanged!
                rc.low64 = nativeToBigEndian(hash.high64);
                rc.high64 = nativeToBigEndian(hash.low64);
            }
            assert(ec == XXH_errorcode.XXH_OK, "freestate failed");
            state = null;

            return (cast(ubyte*) &rc)[0 .. rc.sizeof];
        }
}
///
@safe unittest
{
    // Simple example using the XXH_64 digest
    XXHTemplate!(XXH64_hash_t, XXH64_state_t, false) hash1;
    hash1.start();
    hash1.put(cast(ubyte) 0);
    auto result = hash1.finish();
}

alias XXH_32 = XXHTemplate!(XXH32_hash_t, XXH32_state_t, false); /// XXH_32 for XXH, 32bit, hash is ubyte[4]
alias XXH_64 = XXHTemplate!(XXH64_hash_t, XXH64_state_t, false); /// XXH_64 for XXH, 64bit, hash is ubyte[8]
alias XXH3_64 = XXHTemplate!(XXH64_hash_t, XXH3_state_t, true); /// XXH3_64 for XXH3, 64bits, hash is ubyte[8]
alias XXH3_128 = XXHTemplate!(XXH128_hash_t, XXH3_state_t, true); /// XXH3_128 for XXH3, 128bits, hash is ubyte[16]

///
@safe unittest
{
    //Simple example
    XXH_32 hash1;
    hash1.start();
    hash1.put(cast(ubyte) 0);
    auto result = hash1.finish();
}
///
@safe unittest
{
    //Simple example
    XXH_64 hash1;
    hash1.start();
    hash1.put(cast(ubyte) 0);
    auto result = hash1.finish();
}
///
@safe unittest
{
    //Simple example
    XXH3_64 hash1;
    hash1.start();
    hash1.put(cast(ubyte) 0);
    auto result = hash1.finish();
}
///
@safe unittest
{
    //Simple example
    XXH3_128 hash1;
    hash1.start();
    hash1.put(cast(ubyte) 0);
    auto result = hash1.finish();
}

///
@safe unittest
{
    //Simple example, hashing a string using xxh32Of helper function
    auto hash = xxh32Of("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "32D153FF");
}
///
@safe unittest
{
    //Simple example, hashing a string using xxh32Of helper function
    auto hash = xxh64Of("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "44BC2CF5AD770999" ); // XXH64
}
///
@safe unittest
{
    //Simple example, hashing a string using xxh32Of helper function
    auto hash = xxh3_64Of("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "78AF5F94892F3950" ); // XXH3/64
}
///
@safe unittest
{
    //Simple example, hashing a string using xxh32Of helper function
    auto hash = xxh128Of("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "06B05AB6733A618578AF5F94892F3950");

}

///
@safe unittest
{
    //Using the basic API
    XXH_32 hash;
    hash.start();
    ubyte[1024] data;
    //Initialize data here...
    hash.put(data);
    ubyte[4] result = hash.finish();
}
///
@safe unittest
{
    //Using the basic API
    XXH_64 hash;
    hash.start();
    ubyte[1024] data;
    //Initialize data here...
    hash.put(data);
    ubyte[8] result = hash.finish();
}
///
@safe unittest
{
    //Using the basic API
    XXH3_64 hash;
    hash.start();
    ubyte[1024] data;
    //Initialize data here...
    hash.put(data);
    ubyte[8] result = hash.finish();
}
///
@safe unittest
{
    //Using the basic API
    XXH3_128 hash;
    hash.start();
    ubyte[1024] data;
    //Initialize data here...
    hash.put(data);
    ubyte[16] result = hash.finish();
}

///
@safe unittest
{
    //Let's use the template features:
    void doSomething(T)(ref T hash)
    if (isDigest!T)
    {
        hash.put(cast(ubyte) 0);
    }
    XXH_32 xxh;
    xxh.start();
    doSomething(xxh);
    auto hash = xxh.finish;
    assert(toHexString(hash) == "CF65B03E", "Got " ~ toHexString(hash));
}
///
@safe unittest
{
    //Let's use the template features:
    void doSomething(T)(ref T hash)
    if (isDigest!T)
    {
        hash.put(cast(ubyte) 0);
    }
    XXH_64 xxh;
    xxh.start();
    doSomething(xxh);
    auto hash = xxh.finish;
    assert(toHexString(hash) == "E934A84ADB052768", "Got " ~ toHexString(hash));
}
///
@safe unittest
{
    //Let's use the template features:
    void doSomething(T)(ref T hash)
    if (isDigest!T)
    {
        hash.put(cast(ubyte) 0);
    }
    XXH3_64 xxh;
    xxh.start();
    doSomething(xxh);
    auto hash = xxh.finish;
    assert(toHexString(hash) == "C44BDFF4074EECDB", "Got " ~ toHexString(hash));
}
///
@safe unittest
{
    //Let's use the template features:
    void doSomething(T)(ref T hash)
    if (isDigest!T)
    {
        hash.put(cast(ubyte) 0);
    }
    XXH3_128 xxh;
    xxh.start();
    doSomething(xxh);
    auto hash = xxh.finish;
    assert(toHexString(hash) == "A6CD5E9392000F6AC44BDFF4074EECDB", "Got " ~ toHexString(hash));
}

///
@safe unittest
{
    assert(isDigest!XXH_32);
    assert(isDigest!XXH_64);
    assert(isDigest!XXH3_64);
    assert(isDigest!XXH3_128);
}

@system unittest
{
    import std.range;
    import std.conv : hexString;

    ubyte[4] digest32;
    ubyte[8] digest64;
    ubyte[16] digest128;

    XXH_32 xxh;
    xxh.put(cast(ubyte[])"abcdef");
    xxh.start();
    xxh.put(cast(ubyte[])"");
    assert(xxh.finish() == cast(ubyte[]) hexString!"02cc5d05");

    digest32 = xxh32Of("");
    assert(digest32 == cast(ubyte[]) hexString!"02cc5d05");
    digest64 = xxh64Of("");
    assert(digest64 == cast(ubyte[]) hexString!"EF46DB3751D8E999", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of("");
    assert(digest64 == cast(ubyte[]) hexString!"2D06800538D394C2", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of("");
    assert(digest128 == cast(ubyte[]) hexString!"99AA06D3014798D86001C324468D497F", "Got " ~ toHexString(digest128));

    digest32 = xxh32Of("a");
    assert(digest32 == cast(ubyte[]) hexString!"550d7456");
    digest64 = xxh64Of("a");
    assert(digest64 == cast(ubyte[]) hexString!"D24EC4F1A98C6E5B", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of("a");
    assert(digest64 == cast(ubyte[]) hexString!"E6C632B61E964E1F", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of("a");
    assert(digest128 == cast(ubyte[]) hexString!"A96FAF705AF16834E6C632B61E964E1F", "Got " ~ toHexString(digest128));

    digest32 = xxh32Of("abc");
    assert(digest32 == cast(ubyte[]) hexString!"32D153FF");
    digest64 = xxh64Of("abc");
    assert(digest64 == cast(ubyte[]) hexString!"44BC2CF5AD770999");
    digest64 = xxh3_64Of("abc");
    assert(digest64 == cast(ubyte[]) hexString!"78AF5F94892F3950");
    digest128 = xxh128Of("abc");
    assert(digest128 == cast(ubyte[]) hexString!"06B05AB6733A618578AF5F94892F3950");

    digest32 = xxh32Of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert(digest32 == cast(ubyte[]) hexString!"89ea60c3");
    digest64 = xxh64Of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert(digest64 == cast(ubyte[]) hexString!"F06103773E8585DF", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert(digest64 == cast(ubyte[]) hexString!"5BBCBBABCDCC3D3F", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert(digest128 == cast(ubyte[]) hexString!"3D62D22A5169B016C0D894FD4828A1A7", "Got " ~ toHexString(digest128));

    digest32 = xxh32Of("message digest");
    assert(digest32 == cast(ubyte[]) hexString!"7c948494");
    digest64 = xxh64Of("message digest");
    assert(digest64 == cast(ubyte[]) hexString!"066ED728FCEEB3BE", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of("message digest");
    assert(digest64 == cast(ubyte[]) hexString!"160D8E9329BE94F9", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of("message digest");
    assert(digest128 == cast(ubyte[]) hexString!"34AB715D95E3B6490ABFABECB8E3A424", "Got " ~ toHexString(digest128));

    digest32 = xxh32Of("abcdefghijklmnopqrstuvwxyz");
    assert(digest32 == cast(ubyte[]) hexString!"63a14d5f");
    digest64 = xxh64Of("abcdefghijklmnopqrstuvwxyz");
    assert(digest64 == cast(ubyte[]) hexString!"CFE1F278FA89835C", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of("abcdefghijklmnopqrstuvwxyz");
    assert(digest64 == cast(ubyte[]) hexString!"810F9CA067FBB90C", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of("abcdefghijklmnopqrstuvwxyz");
    assert(digest128 == cast(ubyte[]) hexString!"DB7CA44E84843D67EBE162220154E1E6", "Got " ~ toHexString(digest128));

    digest32 = xxh32Of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    assert(digest32 == cast(ubyte[]) hexString!"9c285e64");
    digest64 = xxh64Of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    assert(digest64 == cast(ubyte[]) hexString!"AAA46907D3047814", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    assert(digest64 == cast(ubyte[]) hexString!"643542BB51639CB2", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    assert(digest128 == cast(ubyte[]) hexString!"5BCB80B619500686A3C0560BD47A4FFB", "Got " ~ toHexString(digest128));

    digest32 = xxh32Of("1234567890123456789012345678901234567890"~
                    "1234567890123456789012345678901234567890");
    assert(digest32 == cast(ubyte[]) hexString!"9c05f475");
    digest64 = xxh64Of("1234567890123456789012345678901234567890"~
                    "1234567890123456789012345678901234567890");
    assert(digest64 == cast(ubyte[]) hexString!"E04A477F19EE145D", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of("1234567890123456789012345678901234567890"~
                    "1234567890123456789012345678901234567890");
    assert(digest64 == cast(ubyte[]) hexString!"7F58AA2520C681F9", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of("1234567890123456789012345678901234567890"~
                    "1234567890123456789012345678901234567890");
    assert(digest128 == cast(ubyte[]) hexString!"08DD22C3DDC34CE640CB8D6AC672DCB8", "Got " ~ toHexString(digest128));

    enum ubyte[16] input = cast(ubyte[16]) hexString!"c3fcd3d76192e4007dfb496cca67e13b";
    assert(toHexString(input)
        == "C3FCD3D76192E4007DFB496CCA67E13B");

    ubyte[] onemilliona = new ubyte[1000000];
    onemilliona[] = 'a';
    digest32 = xxh32Of(onemilliona);
    assert(digest32 == cast(ubyte[]) hexString!"E1155920", "Got " ~ toHexString(digest32));
    digest64 = xxh64Of(onemilliona);
    assert(digest64 == cast(ubyte[]) hexString!"DC483AAA9B4FDC40", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of(onemilliona);
    assert(digest64 == cast(ubyte[]) hexString!"B1FD6FAE5285C4EB", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of(onemilliona);
    assert(digest128 == cast(ubyte[]) hexString!"A545DF8E384A9579B1FD6FAE5285C4EB", "Got " ~ toHexString(digest128));

    auto oneMillionRange = repeat!ubyte(cast(ubyte)'a', 1000000);
    digest32 = xxh32Of(oneMillionRange);
    assert(digest32 == cast(ubyte[]) hexString!"E1155920", "Got " ~ toHexString(digest32));
    digest64 = xxh64Of(oneMillionRange);
    assert(digest64 == cast(ubyte[]) hexString!"DC483AAA9B4FDC40", "Got " ~ toHexString(digest64));
    digest64 = xxh3_64Of(oneMillionRange);
    assert(digest64 == cast(ubyte[]) hexString!"B1FD6FAE5285C4EB", "Got " ~ toHexString(digest64));
    digest128 = xxh128Of(oneMillionRange);
    assert(digest128 == cast(ubyte[]) hexString!"A545DF8E384A9579B1FD6FAE5285C4EB", "Got " ~ toHexString(digest128));
}

/**
 * This is a convenience alias for $(REF digest, std,digest) using the
 * XXH implementation.
 */
//simple alias doesn't work here, hope this gets inlined...
auto xxh32Of(T...)(T data)
{
    return digest!(XXH_32, T)(data);
}
/// Ditto
auto xxh64Of(T...)(T data)
{
    return digest!(XXH_64, T)(data);
}
/// Ditto
auto xxh3_64Of(T...)(T data)
{
    return digest!(XXH3_64, T)(data);
}
/// Ditto
auto xxh128Of(T...)(T data)
{
    return digest!(XXH3_128, T)(data);
}

///
@safe unittest
{
    auto hash = xxh32Of("abc");
    assert(hash == digest!XXH_32("abc"));
    auto hash1 = xxh64Of("abc");
    assert(hash1 == digest!XXH_64("abc"));
    auto hash2 = xxh3_64Of("abc");
    assert(hash2 == digest!XXH3_64("abc"));
    auto hash3 = xxh128Of("abc");
    assert(hash3 == digest!XXH3_128("abc"));
}

/**
 * OOP API XXH implementation.
 * See `std.digest` for differences between template and OOP API.
 *
 * This is an alias for $(D $(REF WrapperDigest, std,digest)!XXH_32), see
 * there for more information.
 */
alias XXH32Digest = WrapperDigest!XXH_32;
alias XXH64Digest = WrapperDigest!XXH_64; ///ditto
alias XXH3_64Digest = WrapperDigest!XXH3_64; ///ditto
alias XXH128Digest = WrapperDigest!XXH3_128; ///ditto

///
@safe unittest
{
    //Simple example, hashing a string using Digest.digest helper function
    auto xxh = new XXH32Digest();
    ubyte[] hash = xxh.digest("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "32D153FF");
}
///
@safe unittest
{
    //Simple example, hashing a string using Digest.digest helper function
    auto xxh = new XXH64Digest();
    ubyte[] hash = xxh.digest("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "44BC2CF5AD770999");
}
///
@safe unittest
{
    //Simple example, hashing a string using Digest.digest helper function
    auto xxh = new XXH3_64Digest();
    ubyte[] hash = xxh.digest("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "78AF5F94892F3950");
}
///
@safe unittest
{
    //Simple example, hashing a string using Digest.digest helper function
    auto xxh = new XXH128Digest();
    ubyte[] hash = xxh.digest("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "06B05AB6733A618578AF5F94892F3950");
}

///
@system unittest
{
     //Let's use the OOP features:
    void test(Digest dig)
    {
      dig.put(cast(ubyte) 0);
    }
    auto xxh = new XXH32Digest();
    test(xxh);

    //Let's use a custom buffer:
    ubyte[16] buf;
    ubyte[] result = xxh.finish(buf[]);
    assert(toHexString(result) == "CF65B03E", "Got " ~ toHexString(result));
}
///
@system unittest
{
     //Let's use the OOP features:
    void test(Digest dig)
    {
      dig.put(cast(ubyte) 0);
    }
    auto xxh = new XXH64Digest();
    test(xxh);

    //Let's use a custom buffer:
    ubyte[16] buf;
    ubyte[] result = xxh.finish(buf[]);
    assert(toHexString(result) == "E934A84ADB052768", "Got " ~ toHexString(result));
}
///
@system unittest
{
     //Let's use the OOP features:
    void test(Digest dig)
    {
      dig.put(cast(ubyte) 0);
    }
    auto xxh = new XXH3_64Digest();
    test(xxh);

    //Let's use a custom buffer:
    ubyte[16] buf;
    ubyte[] result = xxh.finish(buf[]);
    assert(toHexString(result) == "C44BDFF4074EECDB", "Got " ~ toHexString(result));
}
///
@system unittest
{
     //Let's use the OOP features:
    void test(Digest dig)
    {
      dig.put(cast(ubyte) 0);
    }
    auto xxh = new XXH128Digest();
    test(xxh);

    //Let's use a custom buffer:
    ubyte[16] buf;
    ubyte[] result = xxh.finish(buf[]);
    assert(toHexString(result) == "A6CD5E9392000F6AC44BDFF4074EECDB", "Got " ~ toHexString(result));
}

@system unittest
{
    import std.conv : hexString;
    auto xxh = new XXH32Digest();
    auto xxh64 = new XXH64Digest();
    auto xxh3_64 = new XXH3_64Digest();
    auto xxh128 = new XXH128Digest();

    xxh.put(cast(ubyte[])"abcdef");
    xxh.reset();
    xxh.put(cast(ubyte[])"");
    assert(xxh.finish() == cast(ubyte[]) hexString!"02cc5d05");

    xxh.put(cast(ubyte[])"abcdefghijklmnopqrstuvwxyz");
    ubyte[20] result;
    auto result2 = xxh.finish(result[]);
    assert(result[0 .. 4] == result2 && result2 == cast(ubyte[]) hexString!"63a14d5f", "Got " ~ toHexString(result));

    debug
    {
        import std.exception;
        assertThrown!Error(xxh.finish(result[0 .. 3]));
    }

    assert(xxh.length == 4);
    assert(xxh64.length == 8);
    assert(xxh3_64.length == 8);
    assert(xxh128.length == 16);

    assert(xxh.digest("") == cast(ubyte[]) hexString!"02cc5d05");
    assert(xxh64.digest("") == cast(ubyte[]) hexString!"EF46DB3751D8E999");
    assert(xxh3_64.digest("") == cast(ubyte[]) hexString!"2D06800538D394C2");
    assert(xxh128.digest("") == cast(ubyte[]) hexString!"99AA06D3014798D86001C324468D497F");

    assert(xxh.digest("a") == cast(ubyte[]) hexString!"550d7456");
    assert(xxh64.digest("a") == cast(ubyte[]) hexString!"D24EC4F1A98C6E5B");
    assert(xxh3_64.digest("a") == cast(ubyte[]) hexString!"E6C632B61E964E1F");
    assert(xxh128.digest("a") == cast(ubyte[]) hexString!"A96FAF705AF16834E6C632B61E964E1F");

    assert(xxh.digest("abc") == cast(ubyte[]) hexString!"32D153FF");
    assert(xxh64.digest("abc") == cast(ubyte[]) hexString!"44BC2CF5AD770999");
    assert(xxh3_64.digest("abc") == cast(ubyte[]) hexString!"78AF5F94892F3950");
    assert(xxh128.digest("abc") == cast(ubyte[]) hexString!"06B05AB6733A618578AF5F94892F3950");

    assert(xxh.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
           == cast(ubyte[]) hexString!"89ea60c3");
    assert(xxh64.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
           == cast(ubyte[]) hexString!"F06103773E8585DF");
    assert(xxh3_64.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
           == cast(ubyte[]) hexString!"5BBCBBABCDCC3D3F");
    assert(xxh128.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
           == cast(ubyte[]) hexString!"3D62D22A5169B016C0D894FD4828A1A7");

    assert(xxh.digest("message digest") == cast(ubyte[]) hexString!"7c948494");
    assert(xxh64.digest("message digest") == cast(ubyte[]) hexString!"066ED728FCEEB3BE");
    assert(xxh3_64.digest("message digest") == cast(ubyte[]) hexString!"160D8E9329BE94F9");
    assert(xxh128.digest("message digest") == cast(ubyte[]) hexString!"34AB715D95E3B6490ABFABECB8E3A424");

    assert(xxh.digest("abcdefghijklmnopqrstuvwxyz") == cast(ubyte[]) hexString!"63a14d5f");
    assert(xxh64.digest("abcdefghijklmnopqrstuvwxyz") == cast(ubyte[]) hexString!"CFE1F278FA89835C");
    assert(xxh3_64.digest("abcdefghijklmnopqrstuvwxyz") == cast(ubyte[]) hexString!"810F9CA067FBB90C");
    assert(xxh128.digest("abcdefghijklmnopqrstuvwxyz") == cast(ubyte[]) hexString!"DB7CA44E84843D67EBE162220154E1E6");

    assert(xxh.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
           == cast(ubyte[]) hexString!"9c285e64");
    assert(xxh64.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
           == cast(ubyte[]) hexString!"AAA46907D3047814");
    assert(xxh3_64.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
           == cast(ubyte[]) hexString!"643542BB51639CB2");
    assert(xxh128.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
           == cast(ubyte[]) hexString!"5BCB80B619500686A3C0560BD47A4FFB");

    assert(xxh.digest("1234567890123456789012345678901234567890",
                                   "1234567890123456789012345678901234567890")
           == cast(ubyte[]) hexString!"9c05f475");
    assert(xxh64.digest("1234567890123456789012345678901234567890",
                                   "1234567890123456789012345678901234567890")
           == cast(ubyte[]) hexString!"E04A477F19EE145D");
    assert(xxh3_64.digest("1234567890123456789012345678901234567890",
                                   "1234567890123456789012345678901234567890")
           == cast(ubyte[]) hexString!"7F58AA2520C681F9");
    assert(xxh128.digest("1234567890123456789012345678901234567890",
                                   "1234567890123456789012345678901234567890")
           == cast(ubyte[]) hexString!"08DD22C3DDC34CE640CB8D6AC672DCB8");
}
