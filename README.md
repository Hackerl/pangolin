<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]



<!-- PROJECT LOGO -->
<br />
<p align="center">
  <h3 align="center">Pangolin</h3>

  <p align="center">
    Inject ELF into remote process.
    <br />
    <br />
    <a href="https://github.com/Hackerl/pangolin/issues">Report Bug</a>
    ·
    <a href="https://github.com/Hackerl/pangolin/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgements">Acknowledgements</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

Pangolin is a program that allows to inject an ELF file into a remote process, both static & dynamically linked programs can be targeted.

### Built With

* [GCC](https://gcc.gnu.org)
* [Make](https://www.gnu.org/software/make)
* [CMake](https://cmake.org)



<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* CMake
  ```sh
  curl https://github.com/Kitware/CMake/releases/download/v3.21.0/cmake-3.21.0-linux-x86_64.sh | sh
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/Hackerl/pangolin.git
   ```
2. Update submodule
   ```sh
   git submodule update --init --recursive
   ```
3. Build shellcode
   ```sh
   make -C shellcode
   ```
4. Build injector
   ```sh
   mkdir -p build && cd build && cmake .. && make
   ```



<!-- USAGE EXAMPLES -->
## Usage

```sh
usage: pangolin [options] pid(int) ... inject argv ...
positional:
        pid                 process id(int)
optional:
        -?, --help          print help message
        -d, --daemon        daemon mode
        -e, --environs      environment variables(string[])
```

Start target:
```sh
./target
```

Inject target:
```sh
./pangolin -e "PANGOLIN=1" $(pidof target) $(pwd)/inject 1 "2 3"
```

If you want to make some threads reside in remote process, please specify daemon mode, pangolin will allocate a persistent memory as stack. In addition, after daemon thread created, call ```exit``` syscall in main thread to end injection.



<!-- ROADMAP -->
## Roadmap

See the [open issues](https://github.com/Hackerl/pangolin/issues) for a list of proposed features (and known issues).



<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request



<!-- LICENSE -->
## License

Distributed under the beerware License.



<!-- CONTACT -->
## Contact

Hackerl - [@Hackerl](https://github.com/Hackerl)

Project Link: [https://github.com/Hackerl/pangolin](https://github.com/Hackerl/pangolin)



<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [mandibule](https://github.com/ixty/mandibule)
* [elf](https://github.com/MikhailProg/elf)
* [printf](https://github.com/mpaland/printf)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/Hackerl/pangolin.svg?style=for-the-badge
[contributors-url]: https://github.com/Hackerl/pangolin/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/Hackerl/pangolin.svg?style=for-the-badge
[forks-url]: https://github.com/Hackerl/pangolin/network/members
[stars-shield]: https://img.shields.io/github/stars/Hackerl/pangolin.svg?style=for-the-badge
[stars-url]: https://github.com/Hackerl/pangolin/stargazers
[issues-shield]: https://img.shields.io/github/issues/Hackerl/pangolin.svg?style=for-the-badge
[issues-url]: https://github.com/Hackerl/pangolin/issues