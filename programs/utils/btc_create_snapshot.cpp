

#include <btc/snapshot/snapshot.hpp>

#include <iostream>
#include <fstream>

using namespace btc::snapshot;


/*
 * 
 */
int main(int argc, char** argv) {
    if (2 == argc) {
        std::cout << "Writing snapshot\n";
        snapshot* snap = makeTestSnapshot();
        std::ofstream snapshot_bin("snapshot.bin", std::ofstream::binary);
        snapshot_bin << *snap;
        prettyPrint(*snap);

    } else {
        std::cout << "Loading snapshot\n";
        std::ifstream* snapshot_bin = new std::ifstream("snapshot.bin", std::ifstream::binary);
        snapshot snap(snapshot_bin);
        prettyPrint(snap.header);
        
        std::array<char,20> hash;
        for (int i = 0; i < 20; i++) {
            hash[i] = 'a' + i;
        }
        std::cout << "found amount:\t" << snap.get_p2pkh(hash).amount << "\n";
        /*
        snapshot* snap = new snapshot();
        snapshot_bin >> *snap;
        prettyPrint(*snap);
         */
        /*
        snapshot_header *header = new snapshot_header();
        snapshot_bin >> *header;
        prettyPrint(*header);
         */ 
    }
    
    return 0;
}

