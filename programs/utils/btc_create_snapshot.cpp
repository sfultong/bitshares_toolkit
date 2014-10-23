

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
        std::ifstream snapshot_bin("snapshot.bin", std::ifstream::binary);
        snapshot* snap = new snapshot();
        snapshot_bin >> *snap;
        prettyPrint(*snap);
        /*
        snapshot_header *header = new snapshot_header();
        snapshot_bin >> *header;
        prettyPrint(*header);
         */ 
    }
    
    return 0;
}

