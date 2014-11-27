#include <btc/snapshot/snapshot.hpp>

#include <iostream>
#include <iomanip>
#include <iterator>
#include <cstring>
#include <fc/crypto/base58.hpp>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h> 
#include <openssl/obj_mac.h>



#define P2PKH_SIZE 28
/*
//should be defined in bn.h
#define BN_zero(a)	(BN_set_word((a),0))

#define NID_secp256k1		714
 */

namespace btc { namespace snapshot {

void prettyPrint(char c) {
    char first = (c & 0xF0) >> 4;
    first = first < 10 ? first + '0' : first + 'A';
    char second = c & 0x0F;
    second = second < 10 ? second + '0' : second + 'A';
    std::cout << first << second;
}
void prettyPrint(const unsigned char* c, int length) {
    int i = 0;
    do {
        prettyPrint (*(c + i));
        
    } while (++i < length);
}
bool equals(const std::array<char,20> &a, const std::array<char,20> &b) {
    for (int i = 0; i < 20; i++) {
        if (a[i] != b[i]) return false;
    }
    
    return true;
}
    
snapshot_header::snapshot_header (void): 
    version(1),
    merkle_root(),
    block_hash(),
    total_claim_value(0),
    num_claims(0),
    p2pkh_offset(BTC_SNAPSHOT_HEADER_OFFSET),
    p2sh_offset(BTC_SNAPSHOT_HEADER_OFFSET),
    multisig_offset(BTC_SNAPSHOT_HEADER_OFFSET),
    raw_script_offset(BTC_SNAPSHOT_HEADER_OFFSET)
{
    // test
    this->merkle_root[0] = 1;
    this->merkle_root[1] = 2;
    this->merkle_root[19] = 0xEE;
}
std::ostream& operator<<(std::ostream &os, const snapshot_header &header) {
    os.write(reinterpret_cast<const char*>(&header.version), sizeof(uint32_t));
    std::copy(header.merkle_root.begin(), header.merkle_root.end(), std::ostream_iterator<char>(os));
    std::copy(header.block_hash.begin(), header.block_hash.end(), std::ostream_iterator<char>(os));
    os.write(reinterpret_cast<const char*>(&header.total_claim_value), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.num_claims), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.p2pkh_offset), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.p2sh_offset), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.multisig_offset), sizeof(uint64_t));
    os.write(reinterpret_cast<const char*>(&header.raw_script_offset), sizeof(uint64_t));
    return os;
}
std::istream& operator>>(std::istream &is, snapshot_header &header) {
    is.read(reinterpret_cast<char*>(&header.version), sizeof(uint32_t));
    //char buf[20 + 32];
    //is.read(buf, 20 + 32);
    // do these work? or do I have to try above approach?
    for (int i = 0; i < 20; i++) { 
        is >> header.merkle_root[i];
    }
    for (int i = 0; i < 32; i++) {
        is >> header.block_hash[i];
    }
    is.read(reinterpret_cast<char*>(&header.total_claim_value), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.num_claims), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.p2pkh_offset), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.p2sh_offset), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.multisig_offset), sizeof(uint64_t));
    is.read(reinterpret_cast<char*>(&header.raw_script_offset), sizeof(uint64_t));
    return is;
}
void prettyPrint (const snapshot_header &header) {
    std::cout << "version\t" << header.version << "\n";
    std::cout << "merkle root\t";
    for (auto &c : header.merkle_root) {
        prettyPrint(c);
        std::cout << " ";
    }
    std::cout << "\n";
    
    std::cout <<"block hash\t";
    for (auto &c : header.block_hash) {
        prettyPrint(c);
        std::cout << " ";
    }
    std::cout << "\n";
    std::cout
            << "total claim value\t" << header.total_claim_value << "\n"
            << "number of claims\t" << header.num_claims << "\n"
            << "p2pkh offset\t" << header.p2pkh_offset << "\n"
            << "p2sh offset\t" << header.p2sh_offset << "\n"
            << "multisig offset\t" << header.multisig_offset << "\n"
            << "raw script offset\t" << header.raw_script_offset << "\n";
}

p2pkh::p2pkh (void) { }
p2pkh::p2pkh (std::array<char,20> _hash, uint64_t _amount): 
    hash(_hash),
    amount(_amount)
{ }
p2pkh::p2pkh (const p2pkh& other):
    hash(other.hash),
    amount(other.amount)
{ }
std::ostream& operator<<(std::ostream &os, const p2pkh &entry) {
    std::copy(entry.hash.begin(), entry.hash.end(), std::ostream_iterator<char>(os));
    os.write(reinterpret_cast<const char*>(&entry.amount), sizeof(uint64_t));
    return os;
}
std::istream& operator>>(std::istream &is, p2pkh &entry) {
    for (int i = 0; i < 20; i++) {
        is >> entry.hash[i];
    }
    is.read(reinterpret_cast<char*>(&entry.amount), sizeof(uint64_t));
    return is;        
}
void prettyPrint (const p2pkh &entry) {
    std::vector<char> vec;
    for (auto &c : entry.hash) {
        vec.push_back(c);
    }
    std::cout << fc::to_base58(vec) << "\t"
            << entry.amount << "\n";
}

snapshot::snapshot(): 
    header(),
    p2pkh_entries()
{ }
snapshot::snapshot(std::ifstream* _ifstream):
        header(),
        p2pkh_entries()
{
    this->ifstream = _ifstream;
    (*_ifstream) >> header;
}
void snapshot::add_p2pkh (const p2pkh& entry) {
    header.p2sh_offset += P2PKH_SIZE;
    header.multisig_offset += P2PKH_SIZE;
    header.raw_script_offset += P2PKH_SIZE;
    header.num_claims++;
    header.total_claim_value += entry.amount;
    p2pkh_entries.push_back(entry);
}
p2pkh* snapshot::get_p2pkh (const std::array<char,20> &hash) {
    // TODO -- use binary search!!!!!!!!!!!!!
    ifstream->seekg(header.p2pkh_offset);
    p2pkh entry;
    uint64_t offset = header.p2pkh_offset;
    while (! equals(entry.hash, hash) && offset < header.p2sh_offset) {
        (*ifstream) >> entry;
        offset += P2PKH_SIZE;
    }
    
    return equals(entry.hash, hash) ? new p2pkh(entry) : nullptr;
}

// taken directly from bitcoin source (key.cpp)
// Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
// recid selects which key is recovered
// if check is non-zero, additional checks are performed
int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, ECDSA_SIG *ecsig, const unsigned char *msg, int msglen, int recid, int check)
{
    if (!eckey) return 0;

    int ret = 0;
    BN_CTX *ctx = NULL;

    BIGNUM *x = NULL;
    BIGNUM *e = NULL;
    BIGNUM *order = NULL;
    BIGNUM *sor = NULL;
    BIGNUM *eor = NULL;
    BIGNUM *field = NULL;
    EC_POINT *R = NULL;
    EC_POINT *O = NULL;
    EC_POINT *Q = NULL;
    BIGNUM *rr = NULL;
    BIGNUM *zero = NULL;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if ((ctx = BN_CTX_new()) == NULL) { ret = -1; goto err; }
    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) { ret = -2; goto err; }
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) { ret=-1; goto err; }
    if (!BN_mul_word(x, i)) { ret=-1; goto err; }
    if (!BN_add(x, x, ecsig->r)) { ret=-1; goto err; }
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx)) { ret=-2; goto err; }
    if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
    if ((R = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)) { ret=0; goto err; }
    if (check)
    {
        if ((O = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) { ret=-2; goto err; }
        if (!EC_POINT_is_at_infinity(group, O)) { ret = 0; goto err; }
    }
    if ((Q = EC_POINT_new(group)) == NULL) { ret = -2; goto err; }
    n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
    if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
    zero = BN_CTX_get(ctx);
    if (!BN_zero(zero)) { ret=-1; goto err; }
    if (!BN_mod_sub(e, zero, e, order, ctx)) { ret=-1; goto err; }
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, ecsig->r, order, ctx)) { ret=-1; goto err; }
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx)) { ret=-1; goto err; }
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) { ret=-1; goto err; }
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) { ret=-2; goto err; }
    if (!EC_KEY_set_public_key(eckey, Q)) { ret=-2; goto err; }

    ret = 1;

err:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (R != NULL) EC_POINT_free(R);
    if (O != NULL) EC_POINT_free(O);
    if (Q != NULL) EC_POINT_free(Q);
    return ret;
}

/*
 * Note that Hash does sha256^2
 *     static unsigned char pblank[1];
    uint256 hash1;
    SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
    uint256 hash2;
    SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
    return hash2;

 * CPubKey pubkey;
    if (!pubkey.RecoverCompact(Hash(ss.begin(), ss.end()), vchSig))

if (!(CBitcoinAddress(pubkey.GetID()) == addr))


bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() != 65)
        return false;
    CECKey key;
    if (!key.Recover(hash, &vchSig[1], (vchSig[0] - 27) & ~4))
        return false;
    key.GetPubKey(*this, (vchSig[0] - 27) & 4);
    return true;
}

    bool Recover(const uint256 &hash, const unsigned char *p64, int rec)
    {
        if (rec<0 || rec>=3)
            return false;
        ECDSA_SIG *sig = ECDSA_SIG_new();
        BN_bin2bn(&p64[0],  32, sig->r);
        BN_bin2bn(&p64[32], 32, sig->s);
        bool ret = ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), rec, 0) == 1;
        ECDSA_SIG_free(sig);
        return ret;
    }

    void GetPubKey(CPubKey &pubkey, bool fCompressed) {
        EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
        int nSize = i2o_ECPublicKey(pkey, NULL);
        assert(nSize);
        assert(nSize <= 65);
        unsigned char c[65];
        unsigned char *pbegin = c;
        int nSize2 = i2o_ECPublicKey(pkey, &pbegin);
        assert(nSize == nSize2);
        pubkey.Set(&c[0], &c[nSize]);
    }

 */


p2pkh* snapshot::get_p2pkh (std::string& claim, std::string& signature) {
    // first, take the sha256 hash of the message twice

    unsigned char c1[32];
    unsigned char* hash1 = c1;
    SHA256((unsigned char*) claim.c_str(), claim.size(), hash1);
    unsigned char c2[32];
    unsigned char* hash2 = c2;
    SHA256(hash1, 32, hash2);
    std::cout << "message hash is ";
    prettyPrint(hash2, 32);
    std::cout << "\n";
    
    // recover public key from message and signature
    const unsigned char* sig_chars = (const unsigned char*) signature.c_str();
    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    int rec = (sig_chars[0] - 27) & ~4;
    const unsigned char* p64 = &sig_chars[1];
    std::cout << "rec is " << rec << "\n"; 
    if (rec<0 || rec>=3 ) return nullptr;  //EXIT POINT
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BN_bin2bn(&p64[0],  32, sig->r);
    BN_bin2bn(&p64[32], 32, sig->s);
    bool ret = ECDSA_SIG_recover_key_GFp(pkey, sig, hash2, 32, rec, 0) == 1;
    ECDSA_SIG_free(sig);
    if (! ret) {
        std::cout << "failed to recover public key\n";
    }
    if (! ret) return nullptr;             //EXIT POINT
    std::cout << "recovered key\n";

    // get octet stream version of public key
    bool fCompressed = (sig_chars[0] - 27) & 4;
    EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);
    int nSize = i2o_ECPublicKey(pkey, NULL);
    assert(nSize);
    assert(nSize <= 65);
    unsigned char c[65];
    unsigned char *pbegin = c;
    int nSize2 = i2o_ECPublicKey(pkey, &pbegin);
    assert(nSize == nSize2);
    std::cout << "got octet version of key\n";
    
    // generate the PKH 
    unsigned char c3[32];
    unsigned char* hash3 = c3;
    SHA256(pbegin, 65, hash3);
    unsigned char c4[20];
    unsigned char* hash4 = c4;
    RIPEMD160(hash3, 32, hash4);
    
    //debug
    std::cout << "Found PKH: ";
    prettyPrint(hash4, 20);
    std::cout <<  "\n";
    
    // find in snapshot
    std::array<char,20> pkh;
    std::memcpy (pkh.data(),hash4,20);
    return get_p2pkh(pkh);
}
std::ostream& operator<<(std::ostream &os, const snapshot &snap) {
    os << snap.header;
    for (auto &entry : snap.p2pkh_entries) {
        os << entry;
    }
    return os;
}
std::istream& operator>>(std::istream &is, snapshot &snap) {
    is >> snap.header;
    p2pkh entry;
    std::cout << "loaded header\n";
    for (uint64_t i = BTC_SNAPSHOT_HEADER_OFFSET; i < snap.header.p2sh_offset; i += P2PKH_SIZE) {
        is >> entry;
        snap.p2pkh_entries.push_back(p2pkh(entry));
        std::cout << "loaded entry\n";
    }
    return is;
}
void prettyPrint (const snapshot &snap) {
    prettyPrint(snap.header);
    std::cout << "-----p2pkh entries-----\n";
    for (auto &entry : snap.p2pkh_entries) {
        prettyPrint(entry);
    }
}
snapshot* makeTestSnapshot () {
    snapshot* snap = new snapshot();
    std::array<char,20> hash1;
    std::array<char,20> hash2;
    std::vector<char> pkh1 = fc::from_base58("1KBYtRBmVnjV6TzjyBu53JeXhNYAWfncbf");
    std::vector<char> pkh2 = fc::from_base58("15GqvW64qWwehgfTqWmzhum76d1RQhEJKj");
    for (int i = 1; i < 21; i++) {
        hash1[i - 1] = pkh1[i];
        hash2[i - 1] = pkh2[i];
    }
    
    snap->add_p2pkh(p2pkh(hash1, 11));
    snap->add_p2pkh(p2pkh(hash2, 22));
    
    return snap;
}



    
} } // btc::snapshot