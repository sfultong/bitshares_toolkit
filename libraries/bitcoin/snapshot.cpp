#include <btc/snapshot/snapshot.hpp>

//#include <cstdlib>
#include <iostream>
#include <iomanip>
/*
#include <iomanip>
#include <fstream>
 */ 
#include <iterator>
#include <fc/crypto/base58.hpp>

#define P2PKH_SIZE 28

namespace btc { namespace snapshot {

void prettyPrint(char c) {
    char first = (c & 0xF0) >> 4;
    first = first < 10 ? first + '0' : first + 'A';
    char second = c & 0x0F;
    second = second < 10 ? second + '0' : second + 'A';
    std::cout << first << second;
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
void snapshot::add_p2pkh (const p2pkh& entry) {
    header.p2sh_offset += P2PKH_SIZE;
    header.multisig_offset += P2PKH_SIZE;
    header.raw_script_offset += P2PKH_SIZE;
    header.num_claims++;
    header.total_claim_value += entry.amount;
    p2pkh_entries.push_back(entry);
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
    for (uint64_t i = BTC_SNAPSHOT_HEADER_OFFSET; i < snap.header.p2sh_offset; i += P2PKH_SIZE) {
        is >> entry;
        snap.p2pkh_entries.push_back(p2pkh(entry));
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
    std::array<char,20> hash;
    for (int i = 0; i < 20; i++) {
        hash[i] = 'a' + i;
    }
    snap->add_p2pkh(p2pkh(hash, 50));
    
    return snap;
}



    
} } // btc::snapshot