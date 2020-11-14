#include <iostream>
#include <unistd.h>

int main(int ac, char ** av, char ** env) {
    std::cout << "# oh hai from pid " << getpid() << std::endl;

    for(int i = 0; i < ac; i++)
        std::cout << "# arg " << i << ": " << av[i] << std::endl;

    for (int i = 0; i < 3; i++) {
        std::cout << "# :)" << std::endl;
        sleep(1);
    }

    std::cout << "# bye!" << std::endl;

    return 0;
}