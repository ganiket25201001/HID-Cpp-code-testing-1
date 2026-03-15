#include <iostream>

#include "core/orchestrator.h"

int main() {
    hidshield::Orchestrator orchestrator;
    if (!orchestrator.Initialize()) {
        std::cerr << "Initialization failed\n";
        return 1;
    }

    orchestrator.RunSinglePass();
    return 0;
}
