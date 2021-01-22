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
2021-01-22 14:32:42 | INFO  |             main.cpp:44  ] inject '/root/pangolin/bin/inject' to process 4128237 at 0x7efcd3000000
2021-01-22 14:32:42 | INFO  |        pt_inject.cpp:47  ] attach process success
2021-01-22 14:32:42 | INFO  |        pt_inject.cpp:179 ] backup memory
2021-01-22 14:32:42 | INFO  |        pt_inject.cpp:184 ] inject code at: 0x557e5be09000 entry: 0x11d size: 0x126
2021-01-22 14:32:42 | INFO  |        pt_inject.cpp:220 ] restore memory
2021-01-22 14:32:42 | INFO  |             main.cpp:65  ] workspace: 0x7efcd288b010
2021-01-22 14:32:42 | INFO  |        pt_inject.cpp:89  ] backup memory
2021-01-22 14:32:42 | INFO  |        pt_inject.cpp:94  ] inject code at: 0x7efcd288c000 entry: 0xb82 size: 0x2240
2021-01-22 14:32:45 | INFO  |        pt_inject.cpp:142 ] exit status: 0
2021-01-22 14:32:45 | INFO  |        pt_inject.cpp:152 ] restore memory
2021-01-22 14:32:45 | INFO  |             main.cpp:77  ] free workspace: 0x7efcd288b010
2021-01-22 14:32:45 | INFO  |        pt_inject.cpp:179 ] backup memory
2021-01-22 14:32:45 | INFO  |        pt_inject.cpp:184 ] inject code at: 0x557e5be09000 entry: 0x26 size: 0x2f
2021-01-22 14:32:45 | INFO  |        pt_inject.cpp:220 ] restore memory
2021-01-22 14:32:45 | INFO  |        pt_inject.cpp:64  ] detach process success

# back to shell 1
...
> elf loader start
> target: /root/pangolin/bin/inject arg: 3 env: 0
> mapping '/root/pangolin/bin/inject' into memory at 0x7efcd3000000
> load segment addr 0x7efcd3000000 len 0x2000 => 0x7efcd3000000
> load segment addr 0x7efcd3201d90 len 0x1000 => 0x7efcd3201000
> max addr 0x7efcd3213000
> loading interp '/lib64/ld-linux-x86-64.so.2'
> mapping '/lib64/ld-linux-x86-64.so.2' into memory at 0x7efcd3213000
> load segment addr 0x7efcd3213000 len 0x23000 => 0x7efcd3213000
> load segment addr 0x7efcd3436bc0 len 0x2000 => 0x7efcd3436000
> max addr 0x7efcd3449000
> eop 0x7efcd3213c20
> setting auxv
> set auxv[3] to 0x7efcd3000040
> set auxv[4] to 0x38
> set auxv[5] to 0x9
> set auxv[9] to 0x7efcd3000ab0
> set auxv[7] to 0x7efcd3000000
> eop 0x7efcd3213c20
> fake stack: 0x7efcd2889de0
> starting ...
# oh hai from pid 4128237
# arg 0: /root/pangolin/bin/inject
# arg 1: 1
# arg 2: 2 3
# env: MANMAP=1
# env: GS=0x0
# env: FS=0x7efcd289eb80
# :)
# :)
# :)
# bye!
...........
```