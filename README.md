# pangolin: linux elf injector
## intro
Based on project [mandibule](https://github.com/ixty/mandibule), separate shellcode from injector.
## installation
### build injector
```shell
git submodule update --init --recursive
mkdir build
cd build
cmake ..
make
```
### build shellcode
```shell
make -C shelcode
mv shellcode/lib* bin
```
## usage
```shell
usage: ./pangolin --pid=int --commandline=string [options] ...
options:
      --daemon         daemon mode
  -p, --pid            pid (int)
  -c, --commandline    injected commandline (string)
  -e, --env            environment variable (string [=])
  -?, --help           print this message
```
## example run
```shell
# in shell 1
$ ./target
> started.
......

# in shell 2
$ ./pangolin -c "$(pwd)/inject 1 '2 3'" -p $(pidof target)
2021-07-18 14:12:19 | INFO  |             main.cpp:31  ] inject '/root/pangolin/bin/inject 1 '2 3'' to process 1620759
2021-07-18 14:12:19 | INFO  |        pt_inject.cpp:47  ] attach process success
2021-07-18 14:12:19 | INFO  |        pt_inject.cpp:180 ] backup memory
2021-07-18 14:12:19 | INFO  |        pt_inject.cpp:185 ] inject code at: 0x5590aefe7000 entry: 0x71 size: 0x1e4
2021-07-18 14:12:19 | INFO  |        pt_inject.cpp:222 ] restore memory
2021-07-18 14:12:19 | INFO  |             main.cpp:52  ] workspace: 0x7f93b7291010
2021-07-18 14:12:19 | INFO  |        pt_inject.cpp:89  ] backup memory
2021-07-18 14:12:19 | INFO  |        pt_inject.cpp:94  ] inject code at: 0x7f93b7292000 entry: 0x8f size: 0x1fa4
2021-07-18 14:12:22 | INFO  |        pt_inject.cpp:143 ] exit status: 0
2021-07-18 14:12:22 | INFO  |        pt_inject.cpp:153 ] restore memory
2021-07-18 14:12:22 | INFO  |             main.cpp:89  ] free workspace: 0x7f93b7291010
2021-07-18 14:12:22 | INFO  |        pt_inject.cpp:180 ] backup memory
2021-07-18 14:12:22 | INFO  |        pt_inject.cpp:185 ] inject code at: 0x5590aefe7000 entry: 0x20 size: 0x80
2021-07-18 14:12:22 | INFO  |        pt_inject.cpp:222 ] restore memory
2021-07-18 14:12:22 | INFO  |        pt_inject.cpp:64  ] detach process success

# back to shell 1
...
> arg[0] /root/pangolin/bin/inject
> arg[1] 1
> arg[2] 2 3
> mapping /lib64/ld-linux-x86-64.so.2
> segment base: 0x7f93b6233000[0x226000]
> segment: 0x7f93b6233000[0x23000]
> segment: 0x7f93b6456000[0x3000]
> mapping /root/pangolin/bin/inject
> segment base: 0x7f93b6030000[0x203000]
> segment: 0x7f93b6030000[0x2000]
> segment: 0x7f93b6231000[0x2000]
# oh hai from pid 1620759
# arg 0: /root/pangolin/bin/inject
# arg 1: 1
# arg 2: 2 3
# :)
# :)
# :)
# bye!
...........
```