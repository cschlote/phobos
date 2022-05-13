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

/* *************************************
*  Version
***************************************/
enum XXH_VERSION_MAJOR   = 0;
enum XXH_VERSION_MINOR   = 8;
enum XXH_VERSION_RELEASE = 1;
/*! @brief Version number, encoded as two digits each */
enum XXH_VERSION_NUMBER = (XXH_VERSION_MAJOR *100*100 + XXH_VERSION_MINOR *100 + XXH_VERSION_RELEASE);

private import std.stdint;
//private import std.int128;

alias XXH32_hash_t = uint32_t;
alias XXH64_hash_t = uint64_t;
struct XXH128_hash_t {
    XXH64_hash_t low64;   /*!< `value & 0xFFFFFFFFFFFFFFFF` */
    XXH64_hash_t high64;  /*!< `value >> 64` */
}

alias XXH32_canonical_t = uint32_t;
alias XXH64_canonical_t = uint64_t;
alias XXH128_canonical_t = XXH128_hash_t;

struct XXH32_state_t;
struct XXH64_state_t;
struct XXH3_state_t;


enum XXH_errorcode {
    XXH_OK = 0, /*!< OK */
    XXH_ERROR   /*!< Error */
}

uint XXH_expectedVersionNumber ()  @trusted pure nothrow @nogc { return XXH_VERSION_NUMBER; }

@safe unittest
{
    import std.format : format;
    assert(XXH_expectedVersionNumber() == XXH_versionNumber(),
        format(
            "Upstream C version mismatches expected version (C version is %08x, D expects %08x)",
            XXH_versionNumber(), XXH_expectedVersionNumber ()
            ));
}

extern (C) {
    uint XXH_versionNumber () @trusted pure nothrow @nogc;

    XXH32_hash_t XXH32 (const void* input, size_t length, XXH32_hash_t seed) @trusted pure nothrow @nogc;
    XXH32_state_t* XXH32_createState() @trusted pure nothrow @nogc;
    XXH_errorcode  XXH32_freeState(XXH32_state_t* statePtr) @trusted pure nothrow @nogc;
    void XXH32_copyState(XXH32_state_t* dst_state, const XXH32_state_t* src_state) @trusted pure nothrow @nogc;
    XXH_errorcode XXH32_reset  (XXH32_state_t* statePtr, XXH32_hash_t seed) @trusted pure nothrow @nogc;
    XXH_errorcode XXH32_update (XXH32_state_t* statePtr, const void* input, size_t length) @trusted pure nothrow @nogc;
    XXH32_hash_t XXH32_digest (const XXH32_state_t* statePtr) @trusted pure nothrow @nogc;
    void XXH32_canonicalFromHash(XXH32_canonical_t* dst, XXH32_hash_t hash) @trusted pure nothrow @nogc;
    XXH32_hash_t XXH32_hashFromCanonical(const XXH32_canonical_t* src) @trusted pure nothrow @nogc;

    XXH64_hash_t XXH64(const void* input, size_t length, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH64_state_t* XXH64_createState() @trusted pure nothrow @nogc;
    XXH_errorcode  XXH64_freeState(XXH64_state_t* statePtr) @trusted pure nothrow @nogc;
    void XXH64_copyState(XXH64_state_t* dst_state, const XXH64_state_t* src_state) @trusted pure nothrow @nogc;
    XXH_errorcode XXH64_reset  (XXH64_state_t* statePtr, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH_errorcode XXH64_update (XXH64_state_t* statePtr, const void* input, size_t length) @trusted pure nothrow @nogc;
    XXH64_hash_t XXH64_digest (const XXH64_state_t* statePtr) @trusted pure nothrow @nogc;
    void XXH64_canonicalFromHash(XXH64_canonical_t* dst, XXH64_hash_t hash) @trusted pure nothrow @nogc;
    XXH64_hash_t XXH64_hashFromCanonical(const XXH64_canonical_t* src) @trusted pure nothrow @nogc;

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
