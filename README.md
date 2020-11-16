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
usage: ./pangolin --pid=int --command=string [options] ...
options:
  -p, --pid        pid (int)
  -c, --command    command line (string)
  -e, --env        env (string [=])
  -b, --base       base address (string [=])
  -?, --help       print this message
```
## example run
```shell
# in shell 1
$ ./target
> started.
......

# in shell 2
$ ./pangolin -c "$(pwd)/inject 1 '2 3'" -p $(pidof target)
2020-11-16 10:06:30 | INFO    | main.cpp        |       main:33   | inject '/root/pangolin/bin/inject' to process 3640632 at 0x559797000000
2020-11-16 10:06:30 | INFO    | pt_inject.cpp   |     attach:39   | attach process success
2020-11-16 10:06:30 | INFO    | pt_inject.cpp   |   callCode:158  | backup memory
2020-11-16 10:06:30 | INFO    | pt_inject.cpp   |   callCode:163  | inject code at: 0x559795d10000 entry: 0x11d size: 0x126
2020-11-16 10:06:30 | INFO    | pt_inject.cpp   |   callCode:188  | restore memory
2020-11-16 10:06:30 | INFO    | main.cpp        |       main:46   | malloc memory: 0x7f05b2bc3010
2020-11-16 10:06:30 | INFO    | pt_inject.cpp   |    runCode:79   | backup memory
2020-11-16 10:06:30 | INFO    | pt_inject.cpp   |    runCode:84   | inject code at: 0x7f05b2bc4000 entry: 0x9bf size: 0x1fa0
2020-11-16 10:06:33 | INFO    | pt_inject.cpp   |    runCode:126  | cancel exit syscall
2020-11-16 10:06:33 | INFO    | pt_inject.cpp   |    runCode:121  | break exit syscall
2020-11-16 10:06:33 | INFO    | pt_inject.cpp   |    runCode:131  | restore memory
2020-11-16 10:06:33 | INFO    | main.cpp        |       main:56   | free memory: 0x7f05b2bc3010
2020-11-16 10:06:33 | INFO    | pt_inject.cpp   |   callCode:158  | backup memory
2020-11-16 10:06:33 | INFO    | pt_inject.cpp   |   callCode:163  | inject code at: 0x559795d10000 entry: 0x26 size: 0x2f
2020-11-16 10:06:33 | INFO    | pt_inject.cpp   |   callCode:188  | restore memory
2020-11-16 10:06:33 | INFO    | pt_inject.cpp   |     detach:54   | detach process success

# back to shell 1
...
> elf loader start
> target: /root/pangolin/bin/inject arg: 3 env: 0
> mapping '/root/pangolin/bin/inject' into memory at 0x559797000000
> load segment addr 0x559797000000 len 0x1000 => 0x559797000000
> load segment addr 0x559797201d90 len 0x1000 => 0x559797201000
> max addr 0x559797213000
> loading interp '/lib64/ld-linux-x86-64.so.2'
> mapping '/lib64/ld-linux-x86-64.so.2' into memory at 0x559797213000
> load segment addr 0x559797213000 len 0x23000 => 0x559797213000
> load segment addr 0x559797436bc0 len 0x2000 => 0x559797436000
> max addr 0x559797449000
> eop 0x559797213c20
> setting auxv
> set auxv[3] to 0x559797000040
> set auxv[5] to 0x9
> set auxv[9] to 0x559797000ab0
> set auxv[7] to 0x559797000000
> eop 0x559797213c20
> arg 0: /root/pangolin/bin/inject
> arg 1: 1
> arg 2: 2 3
> fake stack: 0xdcd4db70
> starting ...
# oh hai from pid 3640632
# arg 0: /root/pangolin/bin/inject
# arg 1: 1
# arg 2: 2 3
# :)
# :)
# :)
# bye!
...........
```
PS: run "./pangolin -c $(pwd)/inject -p $(pidof target) -e LD_DEBUG=all" for environment variable test.