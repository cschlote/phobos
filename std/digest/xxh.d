/**
 * Computes xxHash hashes of arbitrary data. xxHash hashes are either uint32_t, uint64_t or uint128_t quantities that are like a
 * checksum or CRC, but are more robust and very performant.
 *
$(SCRIPT inhibitQuickIndex = 1;)

$(DIVC quickindex,
$(BOOKTABLE ,
$(TR $(TH Category) $(TH Functions)
)
$(TR $(TDNW Template API) $(TD $(MYREF XXH)
)
)
$(TR $(TDNW OOP API) $(TD $(MYREF XXH32Digest))
)
$(TR $(TDNW Helpers) $(TD $(MYREF xxhOf))
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
 *      $(LINK2https://github.com/Cyan4973/xxHash, GitHub website of project)
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
    Xxh32 xxh;
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
};

extern (C) {
    uint XXH_versionNumber ();

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
    XXH64_hash_t XXH3_64bits_withSecret(const void* data, size_t len, const void* secret, size_t secretSize) @trusted pure nothrow @nogc;
    XXH3_state_t* XXH3_createState() @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_freeState(XXH3_state_t* statePtr) @trusted pure nothrow @nogc;
    void XXH3_copyState(XXH3_state_t* dst_state, const XXH3_state_t* src_state) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_reset(XXH3_state_t* statePtr) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_reset_withSeed(XXH3_state_t* statePtr, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_reset_withSecret(XXH3_state_t* statePtr, const void* secret, size_t secretSize) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_update (XXH3_state_t* statePtr, const void* input, size_t length) @trusted pure nothrow @nogc;
    XXH64_hash_t  XXH3_64bits_digest (const XXH3_state_t* statePtr) @trusted pure nothrow @nogc;

    XXH128_hash_t XXH3_128bits(const void* data, size_t len) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSeed(const void* data, size_t len, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSecret(const void* data, size_t len, const void* secret, size_t secretSize) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_reset(XXH3_state_t* statePtr) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_reset_withSeed(XXH3_state_t* statePtr, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_reset_withSecret(XXH3_state_t* statePtr, const void* secret, size_t secretSize) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_update (XXH3_state_t* statePtr, const void* input, size_t length) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_digest (const XXH3_state_t* statePtr) @trusted pure nothrow @nogc;

    int XXH128_isEqual(XXH128_hash_t h1, XXH128_hash_t h2) @trusted pure nothrow @nogc;
    int XXH128_cmp(const void* h128_1, const void* h128_2) @trusted pure nothrow @nogc;
    void XXH128_canonicalFromHash(XXH128_canonical_t* dst, XXH128_hash_t hash) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH128_hashFromCanonical(const XXH128_canonical_t* src) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH128(const void* data, size_t len, XXH64_hash_t seed) @trusted pure nothrow @nogc;

    XXH_errorcode XXH3_generateSecret(void* secretBuffer, size_t secretSize, const void* customSeed, size_t customSeedSize) @trusted pure nothrow @nogc;
    void XXH3_generateSecret_fromSeed(void* secretBuffer, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    uint XXH_versionNumber ()  @trusted pure nothrow @nogc { return XXH_VERSION_NUMBER; }
    XXH64_hash_t  XXH3_64bits_dispatch(const void* input, size_t len) @trusted pure nothrow @nogc;
    XXH64_hash_t  XXH3_64bits_withSeed_dispatch(const void* input, size_t len, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH64_hash_t  XXH3_64bits_withSecret_dispatch(const void* input, size_t len, const void* secret, size_t secretLen) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_64bits_update_dispatch(XXH3_state_t* state, const void* input, size_t len) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_dispatch(const void* input, size_t len) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSeed_dispatch(const void* input, size_t len, XXH64_hash_t seed) @trusted pure nothrow @nogc;
    XXH128_hash_t XXH3_128bits_withSecret_dispatch(const void* input, size_t len, const void* secret, size_t secretLen) @trusted pure nothrow @nogc;
    XXH_errorcode XXH3_128bits_update_dispatch(XXH3_state_t* state, const void* input, size_t len) @trusted pure nothrow @nogc;
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
 * Template API XXH implementation.
 * See `std.digest` for differences between template and OOP API.
 */
struct XXH(HASH, STATE)
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
         * XXH dig;
         * dig.put(cast(ubyte) 0); //single ubyte
         * dig.put(cast(ubyte) 0, cast(ubyte) 0); //variadic
         * ubyte[10] buf;
         * dig.put(buf); //buffer
         * ----
         */
        void put(scope const(ubyte)[] data...) @trusted pure nothrow @nogc
        {
            XXH_errorcode ec;
            //assert (state != null, "You must call start before puting bytes.");
            if (state == null) this.start;
            static if (digestSize == 32)
                ec = XXH32_update(state, data.ptr, data.length);
            else static if (digestSize == 64)
                ec = XXH64_update(state, data.ptr, data.length);
            else static if (digestSize == 128)
                ec = XXH3_128bits_update(state, data.ptr, data.length);
            assert (ec == XXH_errorcode.XXH_OK, "Update failed");
        }

        /**
         * Used to (re)initialize the XXH digest.
         *
         * Example:
         * --------
         * XXH digest;
         * digest.start();
         * digest.put(0);
         * --------
         */
        void start() @safe pure nothrow @nogc
        {
            this = typeof(this).init;
            XXH_errorcode ec;
            static if (digestSize == 32) {
                if (state == null) state = XXH32_createState();
                ec = XXH32_reset(state, seed);
            } else static if (digestSize == 64) {
                if (state == null) state = XXH64_createState();
                ec = XXH64_reset(state, seed);
            } else static if (digestSize == 128) {
                if (state == null) state = XXH3_createState();
                ec = XXH3_128bits_reset(state);
            }
            //assert (ec == XXH_errorcode.XXH_OK, "reset failed");
        }

        /**
         * Returns the finished XXH hash. This also calls $(LREF start) to
         * reset the internal state.
          */
        ubyte[digestSize/8] finish() @trusted pure nothrow @nogc
        {
            XXH_errorcode ec;
            static if (digestSize == 32) {
                hash = XXH32_digest(state);
                if (state != null) ec = XXH32_freeState(state);
                auto rc = nativeToBigEndian(hash);
            } else static if (digestSize == 64) {
                hash = XXH64_digest(state);
                if (state != null) ec = XXH64_freeState(state);
                auto rc = nativeToBigEndian(hash);
            } else static if (digestSize == 128) {
                hash = XXH3_128bits_digest(state);
                if (state != null) ec = XXH3_freeState(state);
                HASH rc;
                rc.low64 = nativeToBigEndian(hash.low64);
                rc.high64 = nativeToBigEndian(hash.high64);
            }
            assert (ec == XXH_errorcode.XXH_OK, "freestate failed");
            state = null;
            
            return (cast(ubyte*) &rc)[0 .. rc.sizeof];
        }
        ///
        @safe unittest
        {
            //Simple example
            XXH!(HASH, STATE) hash1;
            hash1.start();
            hash1.put(cast(ubyte) 0);
            auto result = hash1.finish();
        }
}
alias Xxh32 = XXH!(XXH32_hash_t, XXH32_state_t);
alias Xxh64 = XXH!(XXH64_hash_t, XXH64_state_t);
//alias Xxh3_64 = XXH!(XXH64_hash_t, XXH64_state_t);
alias Xxh128 = XXH!(XXH128_hash_t, XXH3_state_t);

///
@safe unittest
{
    //Simple example, hashing a string using xxhOf helper function
    auto hash = xxhOf("abc");
    //Let's get a hash string
    assert(toHexString(hash) == "32D153FF");
}

///
@safe unittest
{
    //Using the basic API
    Xxh32 hash;
    hash.start();
    ubyte[1024] data;
    //Initialize data here...
    hash.put(data);
    ubyte[4] result = hash.finish();
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
    Xxh32 xxh;
    xxh.start();
    doSomething(xxh);
    auto hash = xxh.finish;
    assert(toHexString(hash) == "CF65B03E", "Got " ~ toHexString(hash));
}

///
@safe unittest
{
    assert(isDigest!Xxh32);
    assert(isDigest!Xxh64);
    assert(isDigest!Xxh128);
}

@system unittest
{
    import std.range;
    import std.conv : hexString;

    ubyte[4] digest;

    Xxh32 xxh;
    xxh.put(cast(ubyte[])"abcdef");
    xxh.start();
    xxh.put(cast(ubyte[])"");
    assert(xxh.finish() == cast(ubyte[]) hexString!"02cc5d05");

    digest = xxhOf("");
    assert(digest == cast(ubyte[]) hexString!"02cc5d05");

    digest = xxhOf("a");
    assert(digest == cast(ubyte[]) hexString!"550d7456");

    digest = xxhOf("abc");
    assert(digest == cast(ubyte[]) hexString!"32D153FF");

    digest = xxhOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert(digest == cast(ubyte[]) hexString!"89ea60c3");

    digest = xxhOf("message digest");
    assert(digest == cast(ubyte[]) hexString!"7c948494");

    digest = xxhOf("abcdefghijklmnopqrstuvwxyz");
    assert(digest == cast(ubyte[]) hexString!"63a14d5f");

    digest = xxhOf("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    assert(digest == cast(ubyte[]) hexString!"9c285e64");

    digest = xxhOf("1234567890123456789012345678901234567890"~
                    "1234567890123456789012345678901234567890");
    assert(digest == cast(ubyte[]) hexString!"9c05f475");

    enum ubyte[16] input = cast(ubyte[16]) hexString!"c3fcd3d76192e4007dfb496cca67e13b";
    assert(toHexString(input)
        == "C3FCD3D76192E4007DFB496CCA67E13B");

    ubyte[] onemilliona = new ubyte[1000000];
    onemilliona[] = 'a';
    digest = xxhOf(onemilliona);
    assert(digest == cast(ubyte[]) hexString!"E1155920", "Got " ~ toHexString(digest));

    auto oneMillionRange = repeat!ubyte(cast(ubyte)'a', 1000000);
    digest = xxhOf(oneMillionRange);
    assert(digest == cast(ubyte[]) hexString!"E1155920", "Got " ~ toHexString(digest));
}

/**
 * This is a convenience alias for $(REF digest, std,digest) using the
 * XXH implementation.
 */
//simple alias doesn't work here, hope this gets inlined...
auto xxhOf(T...)(T data)
{
    return digest!(Xxh32, T)(data);
}

///
@safe unittest
{
    auto hash = xxhOf("abc");
    assert(hash == digest!Xxh32("abc"));
}

/**
 * OOP API XXH implementation.
 * See `std.digest` for differences between template and OOP API.
 *
 * This is an alias for $(D $(REF WrapperDigest, std,digest)!XXH), see
 * there for more information.
 */
alias XXH32Digest = WrapperDigest!Xxh32;
alias XXH64Digest = WrapperDigest!Xxh64;
alias XXH128Digest = WrapperDigest!Xxh128;

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

@system unittest
{
    import std.conv : hexString;
    auto xxh = new XXH32Digest();

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

    assert(xxh.digest("") == cast(ubyte[]) hexString!"02cc5d05");

    assert(xxh.digest("a") == cast(ubyte[]) hexString!"550d7456");

    assert(xxh.digest("abc") == cast(ubyte[]) hexString!"32D153FF");

    assert(xxh.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
           == cast(ubyte[]) hexString!"89ea60c3");

    assert(xxh.digest("message digest") == cast(ubyte[]) hexString!"7c948494");

    assert(xxh.digest("abcdefghijklmnopqrstuvwxyz")
           == cast(ubyte[]) hexString!"63a14d5f");

    assert(xxh.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
           == cast(ubyte[]) hexString!"9c285e64");

    assert(xxh.digest("1234567890123456789012345678901234567890",
                                   "1234567890123456789012345678901234567890")
           == cast(ubyte[]) hexString!"9c05f475");
}
