# 服务器磁盘检查与清理记录

检查日期：2026-11-20。初次执行时受沙箱只读限制；用户随后开放了文件系统和网络权限，已完成下述实际清理。

根分区 `/dev/vda1` 为 Btrfs：约 120G 总量、88G 已用、31G 可用（清理前）。`/tmp` 为独立 tmpfs。Btrfs 压缩、共享数据块等会使目录 `du` 统计与物理占用不一致，下表不能相加作为释放空间承诺。

| 路径 | `du -sh` | 处理 |
| --- | ---: | --- |
| `/home/Code/work/target` | 24G | 其中 debug/incremental 8.4G 可重建 |
| `/home/Code/mpi/target` | 22G | 其中 debug/incremental 4.0G 可重建 |
| `/home/Code/NodeFlare/target` | 21G | agent/backend 增量缓存约 920M / 5.3G |
| `/home/Code/frp/target` | 14G | 其中 debug/incremental 5.9G 可重建 |
| `/home/Code/novel/target` | 9.5G | 优先清理增量缓存 |
| `/home/Code/CDT-Monitor/target` | 8.2G | 优先清理增量缓存 |
| `/home/Code/AeroBoxForLinux/target` | 7.0G | 其中 debug/incremental 2.0G 可重建 |
| `/home/Code/obs-mount/target` | 6.3G | 优先清理增量缓存 |
| `/root/.rustup/tmp` | 2.0G | 有 10 月遗留的安装临时文件 |
| `/root/.rustup/toolchains/1.88.0-x86_64-unknown-linux-gnu` | 551M | 旧工具链候选 |
| `/root/.rustup/toolchains/1.99.1-x86_64-unknown-linux-gnu` | 716M | 旧工具链候选 |
| `/root/.gradle/caches` | 4.1G | Android 构建可能复用，暂保留 |
| `/root/.cache/go-build` | 2.3G | 当前 Android libbox 构建仍可能复用 |
| `/root/.cargo/registry` | 1.7G | 当前 Rust 离线构建正在使用，保留 |

实际已删除 `/tmp/node-compile-cache` 和 `/tmp/playwright-transform-cache-0` 两个可再生成缓存，共 20,447,232 字节文件分配量（约 19.5 MiB）。这释放 tmpfs 空间，不是根分区磁盘空间。这是早期检查阶段的结果；后续已经完成下文记录的旧增量缓存与工具链清理。

已准备 [清理脚本](../scripts/clean-server-caches.py)。默认只预览；在正常服务器终端中执行下列命令，才会清理上述项目中有标准 Cargo 缓存标记的增量编译目录及超过 7 天的 rustup 临时文件。脚本检查构建进程、缓存标记和路径，不删除 release 成品、node_modules、源码、下载的 crates 或工具链。执行期间不要另开构建。

```sh
cd /home/Code/core
python3 scripts/clean-server-caches.py
python3 scripts/clean-server-caches.py --apply
df -h /
```

本次扫描 `/home/Code` 的 `rust-toolchain*`、构建脚本和 CI 配置未发现 `1.88.0`、`1.99.1` 的固定引用，`rustup override list` 为空。保留 `stable`（包含多个交叉目标）和当前使用的 `1.100.0`。如果服务器其他目录也没有使用两套旧版本，可以通过 rustup 正规卸载：

```sh
rustup toolchain uninstall 1.88.0-x86_64-unknown-linux-gnu 1.99.1-x86_64-unknown-linux-gnu
```

未直接删除 `node_modules`：它们也可能是运行服务的实际依赖，不能仅凭目录体积认定无用。未删除 Playwright 浏览器、Android SDK/NDK 或 Go 工具链，其他本地项目仍可能需要。

## 开放权限后的执行结果

- 已执行 `python3 scripts/clean-server-caches.py --apply`，删除上述 Cargo 增量缓存及 335 个超过 7 天的 rustup 临时文件。根分区可用空间实际增加 **22.78 GiB**，执行后约 54G 可用。
- 再次检查 `/home`、构建配置、服务配置和 rustup override，未发现旧版本固定引用，已通过 rustup 卸载 **1.88.0** 和 **1.99.1**；保留 `stable` 与当前使用的 `1.100.0`。
- 源码、release 成品、Cargo 下载缓存、node_modules、Android SDK/NDK 保留。

## 构建内存临时措施

全量内核测试编译曾触发系统 OOM，日志显示 rustc 常驻内存约 5.23 GB。Cargo 已设为单任务，测试二进制关闭自身调试信息。为完成验证，临时启用 Btrfs NOCOW swapfile `/var/tmp/aerobox-build.swap`（4 GiB），未写入 fstab。任务结束后待内存空闲执行 swapoff 并删除，仅释放此任务创建的文件。

本轮继续删除本任务过期的内核测试可执行文件 `/var/tmp/aerobox-kernel-regression`（376,903,176 字节），当前测试直接使用 Cargo 最新产物。四 ABI 构建和测试新增缓存后根分区约 42G 可用。其他项目正在进行的编译没有清理或中断。

ECH 验证期间额外移除四个已被新测试二进制取代、无运行进程引用的旧 shoes 测试可执行文件（e80e79b1、9554a1f2、aa628dbb、5d4fc737），释放 2.05 GiB；保留当前测试二进制、CLI、Rust 库缓存和 Android 成品。

多网络重连诊断完成后，移除本任务临时保留的旧测试二进制 `/var/tmp/aerobox-network-regression`（分配量 387,821,568 字节）；当前测试直接运行最新 Cargo 产物。

Android 生命周期 10 项通过后，清理已被替代且无进程引用的两份旧 host 测试可执行文件（56617f55、99608c9e），释放 715,374,592 字节分配量；保留最新 8ba7769b 测试与四 ABI 产物。

平台 AAR 与八个新 APK 完成校验归档后，删除被替代的四个 TUIC/多网络旧 APK 和临时 compile-only AAR，共 334.17 MiB；保留旧清单、哈希及替换记录。新的成品位于 `target/android/app-platform/`。本轮继续开发前根分区约 37G 可用。

本轮 CBC/静态 RSA 和 Brutal 专项通过后，清理 17 个过期密码测试二进制与 1 个被新测试取代的旧内核二进制，共 774,852,608 字节分配量（约 739 MiB）。逐项确认无运行进程引用，保留当前测试和 Android 成品；记录位于 `target/android/legacy-brutal/test-binary-cleanup.json`。

2026-11-21 最终 2,860 项回归与八个新 APK 验证完成后，又删除一个被替代且无进程引用的内核测试程序（392,245,248 字节分配量），以及旧平台基线的八个 APK 和一个 AAR（491,651,072 字节分配量），共约 843 MiB。旧 manifest、哈希、测试日志、JVM XML 和 R8/DEX 证据保留；替换记录为 `target/android/app-platform/superseded.json`，新成品为 `target/android/app-legacy-brutal/`。其他项目构建仍在进行，未清理其缓存或中断进程。

2026-11-21 优化基线验收后，核对新旧 App 源码补丁、优化 AAR 和八个 APK 哈希，
删除 `target/android/app-legacy-brutal/` 中已被替代的八个开发版 APK 和开发版 AAR。
保留全部构建/测试/静态审计证据及清理清单 `superseded.json`，实际删除字节数见清单。
当前成品保存在 `target/android/app-legacy-brutal-release/`；未操作其他项目的活跃构建。

2026-11-21 后续主机重启后，恢复了已存在的本任务 4 GiB swapfile（仍未写入 fstab）。
新增 `scripts/run-bounded-build.py` 对本项目构建串行加锁，并通过 systemd/cgroup 设置
MemoryHigh=4 GiB、MemoryMax=5 GiB、MemorySwapMax=1 GiB、TasksMax=256；
Cargo jobs=1、关闭增量，Go GOMAXPROCS=1。硬限额包含该构建的子进程与计入 cgroup
的文件缓存；它不限制其他项目或系统服务。后续测试和四 ABI 构建在同一个受限 scope
中顺序运行，日志持久保存在仓库 `target` 下，避免重启丢失临时验证记录。

主源码的密码层调试和优化验证各 65 项通过后，清理了已经被这些结果取代的
`target/browser-tls-stage/crypto/target`，释放 1,985,265,664 字节分配量（约 1.85 GiB）。
删除前检查了活动进程的命令、工作目录、可执行文件及映射；保留隔离源码、证据和
正在使用的主构建缓存。记录为 `target/android/browser-wire/staging-cache-cleanup.json`。

完整内核编译时，4 GiB 软限额导致持续约 80% 的 cgroup 内存回收等待；在整机可用
内存恢复至约 1.5 GiB 后，仅将当前 scope 的软限额调整为 4.5 GiB。5 GiB 硬限额、
1 GiB 交换限额与串行锁保持生效。调整和内存采样保存在同目录的
`memory-policy-events.jsonl` 与 `memory.jsonl`，不影响其他项目的资源配置。

后续默认构建软限额统一为 4.5 GiB，硬限额仍为 5 GiB、swap 上限 1 GiB，避免已确认的
4 GiB 软限额回收抖动。基础快照内核构建实测 cgroup 峰值 4,908,429,312 字节，未发生
OOM。运行时重协商状态按需分配，只保留一次握手所需的公开 ClientHello 与绑定信息；
其接收缓冲继续有界。

构建控制器现将每秒的cgroup内存、峰值、swap和memory.events保存到
`target/build-control/aerobox-core-build-*.jsonl`，结束时写同名JSON。统计仅针对本任务
scope，峰值字段明确为退出前采样值，不把整机页缓存算作泄漏。

2026-11-21 删除了四种 Android ABI 下已被优化基线取代的 `debug` 交叉编译缓存，
累计目录分配量 17,125,388,288 字节（约 15.95 GiB）。
逐项检查了进程命令、cwd、exe、映射和打开的文件描述符，未发现引用。保留 host 测试缓存、
四 ABI release 缓存与已封存 AAR/APK；没有触碰其他项目。清理期间仍有本项目编译，
根分区可用空间净增加 3.55 GiB；Btrfs 压缩及共享块使该值不同于目录分配量。
记录：`target/android/browser-renegotiation/obsolete-android-debug-cache-cleanup.json`。

2026-11-23 Chrome133接线测试编译期间，4.5 GiB软阈值再次出现持续约80%的回收等待。
当整机仍有约2.6 GiB可用时，仅将当次scope软阈值调到4.75 GiB；硬上限5 GiB、
交换上限1 GiB不变。该scope实测峰值5,102,534,656字节，无OOM或硬上限事件。
默认控制器仍为4.5 GiB；调整记录为`target/chrome-integration-stage/memory-policy.jsonl`，
`target/build-control/aerobox-core-build-32685.json`分别记录初始与最终软阈值。
仅恢复了已有的任务swapfile，未增加交换文件或修改其他项目资源配置。

2026-11-23 Chrome133的开发/优化各75项密码测试、2,863项完整内核回归及16项独立Go
互通通过后，删除79个被该批结果取代的旧密码/内核测试可执行文件，逐项检查了进程命令、
cwd/exe、映射和打开的描述符。删除分配量2,147,532,800字节（约2.00 GiB），
同时构建期间根分区可用空间净增加435,867,648字节（约416 MiB）。保留当前测试程序、
库缓存及Android成品；记录为`target/android/chrome133/test-binary-cleanup.json`。

Chrome133的arm64优化构建中，单个大型LLVM代码生成单元出现大量换页。该scope
峰值4,834,426,880字节、无OOM，但编译进程累计磁盘读取超过400 GB，故主动终止
该轮构建，保留`target/android/chrome133/interrupted-monolithic-codegen/`证据。
Android release现仅对`shoes`覆盖`codegen-units=16`，仍保留优化级别3和thin LTO；
其余包代码生成单元为1。新的构建及监控由临时systemd服务持有，避免交互进程退出
导致监控与构建锁丢失；内存限额仍为4.5/5 GiB、交换上限1 GiB。

2026-11-23 Chrome133四ABI/八APK封存成功后，删除已被替代的CBC/RSA/Naive/Brutal优化版AAR和八个APK：375,932,587字节文件内容、375,947,264字节分配量（约358.5 MiB）。已核对旧SHA256并扫描进程引用；旧manifest、日志和哈希保留，记录为`target/android/chrome133/old-artifact-cleanup.json`。删除后即时statvfs净空闲增量为0，不能把文件分配量当作独占物理空间回收量。最新成品为`target/android/app-chrome133-release/`。

同日修复构建监控的cgroup退出竞态：短任务结束时memory.current可能返回ENODEV，监控继续等待并回收子进程后才释放构建锁；采样异常不会提前解锁。

2026-11-23 BBRv2优化包完成后，再清理已替代的Chrome133 AAR和八个APK：
文件总长430,769,284字节，分配430,784,512字节（约411 MiB）；删除前核对新旧哈希与
所有进程cmdline/maps/fd/cwd/exe，无使用者，旧清单及日志保留。即时可用空间差为0，
不把Btrfs分配值称为物理回收。记录`target/android/bbr2-input/old-artifact-cleanup.json`。
新基线`target/android/app-bbr2-release/manifest.json`保留全部成品。
# 2026-11-23：遗留 rustup 临时文件

核对 `/root/.rustup/tmp` 的 60 个顶层条目均遗留自 2026-11-17，清理前确认无 rustup
安装进程、无进程 cwd/exe/fd/mmap 引用。仅移除这些临时文件，没有卸载 stable 或 1.100.0
工具链，也没有清理其他项目的编译目录。共移除 65,984 个普通文件，逻辑大小
768,736,404 字节，分配量 977,211,392 字节（约 932 MiB）；即时可用空间增加
214,622,208 字节（约 205 MiB）。Btrfs 共享块与同时进行的构建使两者不相同。
逐文件记录保存在 `target/android/android11/rustup-temp-cleanup.json`。


2026-11-25 在 Safari/iOS 安卓指纹验证期间，清理本仓库内已被后续验证替代的 26 个
主机测试可执行文件和 debug 共享库。删除前检查进程 cmdline、内存映射及 cwd/exe/fd
对应 inode；保留最新 Android/Edge/QQ 测试程序、新一轮内核测试程序、依赖库缓存与
当前四 ABI AAR/APK。删除文件分配量 7,884,587,008 字节（约 7.34 GiB），
即时根分区可用空间增加 1,416,794,112 字节（约 1.32 GiB）；两者受 Btrfs 压缩和
共享块影响，不等同。逐文件哈希记录：`target/android-browser-final-stage/obsolete-test-cleanup.json`。
本次未操作其他项目。

同日四 ABI 打包期间，继续删除 95 个已被本轮成功验证替代的旧密码/内核测试程序，
保留最新的 31 类密码测试可执行文件及当前内核测试程序。清理前逐个核对替代结果、
文件哈希及进程 cmdline/maps/cwd/exe/fd 引用。文件逻辑大小 4,578,972,120 字节，
分配量 4,566,933,504 字节；即时根分区空闲增加 1,283,141,632 字节（约 1.20 GiB）。
原始日志、源码、依赖缓存和发行包均保留，记录为
`target/android-browser-final-stage/obsolete-crypto-tests-cleanup.json`。

同日 Firefox 合并验证前，清理 124 个已被新版替代的密码测试可执行文件，保留最新
FFDHE、记录大小、Firefox、DC 开发/发布测试及依赖缓存。删除时持有本仓库构建锁，
检查进程 cmdline/maps/cwd/exe/fd；文件逻辑大小 1,925,461,296 字节，分配量
1,921,003,520 字节。记录：`target/firefox-production-stage/obsolete-crypto-tests-cleanup.json`。

重新核对最新 `target/android/app-browser-profiles-release/` 的 AAR 与全部八个 APK
哈希后，删除更早的 BBRv2 AAR 和八个 APK，保留旧清单、哈希、日志及源码。
九个文件逻辑大小 431,291,706 字节，分配量 431,308,800 字节；清理前确认无进程使用。
`target/android/app-bbr2-release/manifest.json` 现为历史证据，所列二进制已清理。
逐文件记录：`target/firefox-production-stage/obsolete-bbr2-packages-cleanup.json`。
上述分配量不等同于 Btrfs 实际释放量；没有操作其他项目的进程或构建目录。

Firefox 主机合并验收全部通过后，再删除 105 个已替代的主机密码/Android 测试程序，
保留当前 84 个密码测试和 11 个 Android 主机测试可执行文件。此次只删除检查无进程
引用的旧 host 测试文件，正在构建的四 ABI release 库、缓存、源码与封存成品未变。
文件逻辑大小 8,050,410,832 字节，分配量 8,027,521,024 字节；即时可用空间增加
1,906,130,944 字节（约 1.78 GiB），其中也可能含同时运行构建对空闲空间的影响。
逐文件 SHA256 见 `target/firefox-production-stage/post-validation-test-cleanup.json`。

Firefox 四 ABI AAR 和八个 APK 完成封存并再次核对哈希后，清理其替代的上一批
`app-browser-profiles-release` AAR/APK，共九个文件、逻辑大小 432,520,171 字节。
删除前检查进程使用情况，旧清单及验证证据保留；当前完整成品为
`target/android/app-firefox-release/`。记录 `target/android/firefox/old-artifact-cleanup.json`。

2026-11-25：360/randomized合并期间按本项目package精确清除过期Cargo产物：
根target报告579.9MiB、shoes target报告2.3GiB、Android target报告12.3GiB；
完整Firefox安装包一直保留至新包验收。命令、目标与日志在
`target/randomized-production-stage/cleanup-record.json`。这些是Cargo报告的删除量，
不等于Btrfs独占物理空间；重编译会重新占用部分空间。所有构建继续共用锁，
RAM软阈值4.5GiB/硬上限5GiB、swap上限1GiB，没有修改其他项目。

2026-11-26：包含random/360/randomized的四ABI AAR和八个APK完成封存后，
逐个复核新旧SHA256，并确认旧文件没有进程引用，清理被替代的Firefox AAR及八个APK。
删除逻辑大小432,920,875字节、分配量432,939,008字节，删除前后即时可用空间差为0；
不把分配量当作Btrfs独占回收量。旧源码、清单和验证日志保留，记录为
`target/android/randomized/old-artifact-cleanup.json`。最新成品在
`target/android/app-randomized-release/`。本轮App打包内存峰值4,468,207,616字节，
无swap、无OOM；所有编译和测试仍共用受限构建队列。
