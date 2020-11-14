#include <iostream>
#include <unistd.h>

int main() {
    std::cout << "> started." << std::endl;

    for (int i = 0; i < 1000; i++) {
        std::cout << "." << std::flush;
        sleep(1);
    }

    std::cout << "> done." << std::endl;
    return 0;
}