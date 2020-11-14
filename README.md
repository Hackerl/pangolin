# pangolin: linux elf injector
## intro
Based on project [mandibule](https://github.com/ixty/mandibule), separate shellcode from injector.
## installation
### build injector
```shell
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
$ ./pangolin -c $(pwd)/inject -p $(pidof target)
2020-11-14 11:38:55 | INFO    | main.cpp        |       main:37   | inject '/root/pangolin/bin/inject' to process 13527 at 0x55611c000000
2020-11-14 11:38:55 | INFO    | pt_inject.cpp   |     attach:39   | attach process success
2020-11-14 11:38:55 | INFO    | pt_inject.cpp   |   callCode:158  | backup memory
2020-11-14 11:38:55 | INFO    | pt_inject.cpp   |   callCode:163  | inject code at: 0x55611b934000 entry: 0x116 size: 0x11f
2020-11-14 11:38:55 | INFO    | pt_inject.cpp   |   callCode:188  | restore memory
2020-11-14 11:38:55 | INFO    | main.cpp        |       main:50   | malloc memory: 0x7f53cfe1c010
2020-11-14 11:38:55 | INFO    | pt_inject.cpp   |    runCode:79   | backup memory
2020-11-14 11:38:55 | INFO    | pt_inject.cpp   |    runCode:84   | inject code at: 0x7f53cfe1d000 entry: 0x937 size: 0x1ea0
2020-11-14 11:38:58 | INFO    | pt_inject.cpp   |    runCode:126  | cancel exit syscall
2020-11-14 11:38:58 | INFO    | pt_inject.cpp   |    runCode:121  | break exit syscall
2020-11-14 11:38:58 | INFO    | pt_inject.cpp   |    runCode:131  | restore memory
2020-11-14 11:38:58 | INFO    | main.cpp        |       main:60   | free memory: 0x7f53cfe1c010
2020-11-14 11:38:58 | INFO    | pt_inject.cpp   |   callCode:158  | backup memory
2020-11-14 11:38:58 | INFO    | pt_inject.cpp   |   callCode:163  | inject code at: 0x55611b934000 entry: 0x26 size: 0x2f
2020-11-14 11:38:58 | INFO    | pt_inject.cpp   |   callCode:188  | restore memory
2020-11-14 11:38:58 | INFO    | pt_inject.cpp   |     detach:54   | detach process success

# back to shell 1
...
> elf loader start
> target: /root/pangolin/bin/inject arg: 1 env: 0
> mapping '/root/pangolin/bin/inject' into memory at 0x55611c000000
> load segment addr 0x55611c000000 len 0x1000 => 0x55611c000000
> load segment addr 0x55611c001000 len 0x1000 => 0x55611c001000
> load segment addr 0x55611c002000 len 0x1000 => 0x55611c002000
> load segment addr 0x55611c003da0 len 0x1000 => 0x55611c003000
> max addr 0x55611c015000
> loading interp '/lib64/ld-linux-x86-64.so.2'
> mapping '/lib64/ld-linux-x86-64.so.2' into memory at 0x55611c015000
> load segment addr 0x55611c015000 len 0x1000 => 0x55611c015000
> load segment addr 0x55611c016000 len 0x1e000 => 0x55611c016000
> load segment addr 0x55611c034000 len 0x8000 => 0x55611c034000
> load segment addr 0x55611c03c640 len 0x2000 => 0x55611c03c000
> max addr 0x55611c04f000
> eop 0x55611c016090
> setting auxv
> set auxv[3] to 0x55611c000040
> set auxv[5] to 0xb
> set auxv[9] to 0x55611c0010b0
> set auxv[7] to 0x55611c000000
> eop 0x55611c016090
> arg 0: /root/pangolin/bin/inject
> adjust stack
> fake stack: 0x1c3fd500
> starting ...
# oh hai from pid 13527
# arg 0: /root/pangolin/bin/inject
# :)
# :)
# :)
# bye!
...........
```
PS: run "./pangolin -c $(pwd)/inject -p $(pidof target) -e LD_DEBUG=all" for environment variable test.