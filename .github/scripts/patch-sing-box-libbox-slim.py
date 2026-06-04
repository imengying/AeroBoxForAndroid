from pathlib import Path


ROOT = Path.cwd()
DISABLED_BUILD_TAG = "//go:build aerobox_disabled_libbox_feature\n\n"


def read(path: str) -> str:
    return (ROOT / path).read_text()


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text)


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly 1 match, found {count}")
    write(path, text.replace(old, new, 1))


def remove_once(path: str, block: str) -> None:
    replace_once(path, block, "")


def disable_go_file(path: str) -> None:
    file_path = ROOT / path
    if not file_path.exists():
        raise SystemExit(f"{path}: file not found")
    text = file_path.read_text()
    if text.startswith("//go:build "):
        lines = text.splitlines(keepends=True)
        first_non_build = 0
        while first_non_build < len(lines):
            line = lines[first_non_build]
            if line.startswith("//go:build ") or line.startswith("// +build ") or line.strip() == "":
                first_non_build += 1
                continue
            break
        text = "".join(lines[first_non_build:])
    file_path.write_text(DISABLED_BUILD_TAG + text)


def trim_imports(path: str, names: list[str]) -> None:
    text = read(path)
    for name in names:
        text = text.replace(f'\t"{name}"\n', "")
    write(path, text)


def patch_platform_interface() -> None:
    remove_once(
        "experimental/libbox/platform.go",
        "\tStartNeighborMonitor(listener NeighborUpdateListener) error\n"
        "\tCloseNeighborMonitor(listener NeighborUpdateListener) error\n"
        "\tRegisterMyInterface(name string)\n"
        "\tUsePlatformShell() bool\n"
        "\tCheckPlatformShell() error\n"
        "\tOpenShellSession(user *PlatformUser, command string, environ StringIterator, term string, rows int32, cols int32) (ShellSession, error)\n"
        "\tLookupUser(username string) (*PlatformUser, error)\n"
        "\tLookupSFTPServer() (string, error)\n"
        "\tReadSystemSSHHostKey() (string, error)\n"
        "\tTailscaleHostname() string\n",
    )
    remove_once(
        "experimental/libbox/platform.go",
        "\ntype PlatformUser struct {\n"
        "\tUsername string\n"
        "\tUid      int32\n"
        "\tGid      int32\n"
        "\tHomeDir  string\n"
        "\tShell    string\n"
        "\n"
        "\tgroups []int32\n"
        "}\n"
        "\n"
        "func (u *PlatformUser) SetGroups(groups Int32Iterator) {\n"
        "\tu.groups = iteratorToArray[int32](groups)\n"
        "}\n"
        "\n"
        "func (u *PlatformUser) Groups() Int32Iterator {\n"
        "\treturn newIterator(u.groups)\n"
        "}\n"
        "\n"
        "type NeighborUpdateListener interface {\n"
        "\tUpdateNeighborTable(entries NeighborEntryIterator)\n"
        "}\n",
    )


def patch_service_wrapper() -> None:
    remove_once(
        "experimental/libbox/service.go",
        "\tw.iif.RegisterMyInterface(options.Name)\n",
    )
    remove_once(
        "experimental/libbox/service.go",
        "\nfunc (w *platformInterfaceWrapper) UsePlatformNeighborResolver() bool {\n"
        "\treturn true\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn w.iif.StartNeighborMonitor(&neighborUpdateListenerWrapper{listener: listener})\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn w.iif.CloseNeighborMonitor(nil)\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) UsePlatformShell() bool {\n"
        "\treturn w.iif.UsePlatformShell()\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) CheckPlatformShell() error {\n"
        "\treturn w.iif.CheckPlatformShell()\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) OpenShellSession(user *adapter.PlatformUser, command string, environ []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {\n"
        "\tlibboxUser := &PlatformUser{\n"
        "\t\tUsername: user.Username,\n"
        "\t\tUid:      int32(user.Uid),\n"
        "\t\tGid:      int32(user.Gid),\n"
        "\t\tHomeDir:  user.HomeDir,\n"
        "\t\tShell:    user.Shell,\n"
        "\t}\n"
        "\tif len(user.Groups) > 0 {\n"
        "\t\tlibboxUser.SetGroups(newIterator(common.Map(user.Groups, func(g int) int32 { return int32(g) })))\n"
        "\t}\n"
        "\tsession, err := w.iif.OpenShellSession(libboxUser, command, newIterator(environ), term, rows, cols)\n"
        "\tif err != nil {\n"
        "\t\treturn nil, err\n"
        "\t}\n"
        "\treturn session, nil\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) LookupSFTPServer() (string, error) {\n"
        "\treturn w.iif.LookupSFTPServer()\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) ReadSystemSSHHostKey() ([]byte, error) {\n"
        "\tresult, err := w.iif.ReadSystemSSHHostKey()\n"
        "\tif err != nil {\n"
        "\t\treturn nil, err\n"
        "\t}\n"
        "\treturn []byte(result), nil\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) TailscaleHostname() string {\n"
        "\treturn w.iif.TailscaleHostname()\n"
        "}\n"
        "\n"
        "func (w *platformInterfaceWrapper) LookupUser(username string) (*adapter.PlatformUser, error) {\n"
        "\tplatformUser, err := w.iif.LookupUser(username)\n"
        "\tif err != nil {\n"
        "\t\treturn nil, err\n"
        "\t}\n"
        "\treturn &adapter.PlatformUser{\n"
        "\t\tUsername: platformUser.Username,\n"
        "\t\tUid:      int(platformUser.Uid),\n"
        "\t\tGid:      int(platformUser.Gid),\n"
        "\t\tHomeDir:  platformUser.HomeDir,\n"
        "\t\tShell:    platformUser.Shell,\n"
        "\t\tGroups:   common.Map(iteratorToArray[int32](platformUser.Groups()), func(g int32) int { return int(g) }),\n"
        "\t}, nil\n"
        "}\n"
        "\n"
        "type neighborUpdateListenerWrapper struct {\n"
        "\tlistener adapter.NeighborUpdateListener\n"
        "}\n"
        "\n"
        "func (w *neighborUpdateListenerWrapper) UpdateNeighborTable(entries NeighborEntryIterator) {\n"
        "\tvar result []adapter.NeighborEntry\n"
        "\tfor entries.HasNext() {\n"
        "\t\tentry := entries.Next()\n"
        "\t\tif entry == nil {\n"
        "\t\t\tcontinue\n"
        "\t\t}\n"
        "\t\taddress, err := netip.ParseAddr(entry.Address)\n"
        "\t\tif err != nil {\n"
        "\t\t\tcontinue\n"
        "\t\t}\n"
        "\t\tmacAddress, err := net.ParseMAC(entry.MacAddress)\n"
        "\t\tif err != nil {\n"
        "\t\t\tcontinue\n"
        "\t\t}\n"
        "\t\tresult = append(result, adapter.NeighborEntry{\n"
        "\t\t\tAddress:    address,\n"
        "\t\t\tMACAddress: macAddress,\n"
        "\t\t\tHostname:   entry.Hostname,\n"
        "\t\t})\n"
        "\t}\n"
        "\tw.listener.UpdateNeighborTable(result)\n"
        "}\n",
    )

    marker = "\nfunc AvailablePort(startPort int32) (int32, error) {"
    replacement = (
        "\nfunc (w *platformInterfaceWrapper) UsePlatformNeighborResolver() bool {\n"
        "\treturn false\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn E.New(\"platform neighbor resolver is not supported\")\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn nil\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) UsePlatformShell() bool {\n"
        "\treturn false\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) CheckPlatformShell() error {\n"
        "\treturn nil\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) OpenShellSession(user *adapter.PlatformUser, command string, environ []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {\n"
        "\treturn nil, E.New(\"platform shell is not supported\")\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) LookupSFTPServer() (string, error) {\n"
        "\treturn \"\", E.New(\"platform shell is not supported\")\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) ReadSystemSSHHostKey() ([]byte, error) {\n"
        "\treturn nil, E.New(\"platform shell is not supported\")\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) TailscaleHostname() string {\n"
        "\treturn \"\"\n"
        "}\n"
        "\n"
        "\nfunc (w *platformInterfaceWrapper) LookupUser(username string) (*adapter.PlatformUser, error) {\n"
        "\treturn nil, E.New(\"platform shell is not supported\")\n"
        "}\n"
        "\n" + marker
    )
    replace_once("experimental/libbox/service.go", marker, replacement)


def patch_config_stub() -> None:
    remove_once(
        "experimental/libbox/config.go",
        "\nfunc (s *platformInterfaceStub) UsePlatformNeighborResolver() bool {\n"
        "\treturn false\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn os.ErrInvalid\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn nil\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) UsePlatformShell() bool {\n"
        "\treturn false\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) CheckPlatformShell() error {\n"
        "\treturn nil\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) OpenShellSession(user *adapter.PlatformUser, command string, env []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {\n"
        "\treturn nil, os.ErrInvalid\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) LookupSFTPServer() (string, error) {\n"
        "\treturn \"\", os.ErrInvalid\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) ReadSystemSSHHostKey() ([]byte, error) {\n"
        "\treturn nil, os.ErrInvalid\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) TailscaleHostname() string {\n"
        "\treturn \"\"\n"
        "}\n"
        "\n"
        "func (s *platformInterfaceStub) LookupUser(username string) (*adapter.PlatformUser, error) {\n"
        "\treturn nil, os.ErrInvalid\n"
        "}\n",
    )
    marker = "\nfunc (s *platformInterfaceStub) UsePlatformLocalDNSTransport() bool {"
    replacement = (
        "\nfunc (s *platformInterfaceStub) UsePlatformNeighborResolver() bool {\n"
        "\treturn false\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn os.ErrInvalid\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {\n"
        "\treturn nil\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) UsePlatformShell() bool {\n"
        "\treturn false\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) CheckPlatformShell() error {\n"
        "\treturn nil\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) OpenShellSession(user *adapter.PlatformUser, command string, env []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {\n"
        "\treturn nil, os.ErrInvalid\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) LookupSFTPServer() (string, error) {\n"
        "\treturn \"\", os.ErrInvalid\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) ReadSystemSSHHostKey() ([]byte, error) {\n"
        "\treturn nil, os.ErrInvalid\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) TailscaleHostname() string {\n"
        "\treturn \"\"\n"
        "}\n"
        "\n"
        "\nfunc (s *platformInterfaceStub) LookupUser(username string) (*adapter.PlatformUser, error) {\n"
        "\treturn nil, os.ErrInvalid\n"
        "}\n"
        "\n" + marker
    )
    replace_once("experimental/libbox/config.go", marker, replacement)


def patch_command_client() -> None:
    trim_imports(
        "experimental/libbox/command_client.go",
        [
            "io",
            "google.golang.org/grpc/codes",
            "google.golang.org/grpc/status",
        ],
    )
    text = read("experimental/libbox/command_client.go")
    start = text.index("\nfunc (c *CommandClient) TriggerGoCrash() error {")
    end = text.index("\nfunc (c *CommandClient) GetDeprecatedNotes()", start)
    text = text[:start] + text[end:]
    start = text.index("\nfunc (c *CommandClient) StartNetworkQualityTest(")
    write("experimental/libbox/command_client.go", text[:start])


def patch_command_server() -> None:
    remove_once("experimental/libbox/command_server.go", "\tTriggerNativeCrash() error\n")
    remove_once("experimental/libbox/command_server.go", "\tConnectSSHAgent() (int32, error)\n")
    remove_once(
        "experimental/libbox/command_server.go",
        "\t\tOOMKillerEnabled:  sOOMKillerEnabled,\n"
        "\t\tOOMKillerDisabled: sOOMKillerDisabled,\n"
        "\t\tOOMMemoryLimit:    uint64(sOOMMemoryLimit),\n",
    )
    remove_once(
        "experimental/libbox/command_server.go",
        "\tsaveConfigSnapshot(configContent)\n",
    )
    text = read("experimental/libbox/command_server.go")
    start = text.index("\nfunc (h *platformHandler) TriggerNativeCrash() error {")
    replacement = (
        "\nfunc (h *platformHandler) TriggerNativeCrash() error {\n"
        "\treturn nil\n"
        "}\n"
        "\n"
        "func (h *platformHandler) WriteDebugMessage(message string) {\n"
        "\t(*CommandServer)(h).handler.WriteDebugMessage(message)\n"
        "}\n"
        "\n"
        "func (h *platformHandler) ConnectSSHAgent() (int32, error) {\n"
        "\treturn -1, os.ErrInvalid\n"
        "}\n"
    )
    write("experimental/libbox/command_server.go", text[:start] + replacement)


def patch_setup() -> None:
    text = read("experimental/libbox/setup.go")
    old_import = (
        "import (\n"
        "\t\"math\"\n"
        "\t\"os\"\n"
        "\t\"path/filepath\"\n"
        "\t\"runtime\"\n"
        "\t\"runtime/debug\"\n"
        "\t\"strings\"\n"
        "\t\"time\"\n"
        "\n"
        "\t\"github.com/sagernet/sing-box/common/networkquality\"\n"
        "\t\"github.com/sagernet/sing-box/common/stun\"\n"
        "\tC \"github.com/sagernet/sing-box/constant\"\n"
        "\t\"github.com/sagernet/sing-box/dns\"\n"
        "\t\"github.com/sagernet/sing-box/experimental/locale\"\n"
        "\t\"github.com/sagernet/sing-box/log\"\n"
        "\t\"github.com/sagernet/sing-box/service/oomkiller\"\n"
        "\t\"github.com/sagernet/sing/common/byteformats\"\n"
        "\tE \"github.com/sagernet/sing/common/exceptions\"\n"
        ")\n"
    )
    new_import = (
        "import (\n"
        "\t\"os\"\n"
        "\t\"runtime/debug\"\n"
        "\n"
        "\tC \"github.com/sagernet/sing-box/constant\"\n"
        "\t\"github.com/sagernet/sing-box/experimental/locale\"\n"
        ")\n"
    )
    text = text.replace(old_import, new_import, 1)
    for block in [
        "\tsCrashReportSource       string\n"
        "\tsOOMKillerEnabled        bool\n"
        "\tsOOMKillerDisabled       bool\n"
        "\tsOOMMemoryLimit          int64\n",
        "\tCrashReportSource       string\n"
        "\tOomKillerEnabled        bool\n"
        "\tOomKillerDisabled       bool\n"
        "\tOomMemoryLimit          int64\n",
        "\tsCrashReportSource = options.CrashReportSource\n"
        "\tReloadSetupOptions(options)\n",
    ]:
        if block not in text:
            raise SystemExit("setup.go: expected block not found")
        text = text.replace(block, "", 1)
    start = text.index("\nfunc ReloadSetupOptions(options *SetupOptions) {")
    end = text.index("\nfunc Setup(options *SetupOptions) error {", start)
    text = text[:start] + text[end:]
    text = text.replace(
        "\treturn redirectStderr(filepath.Join(sWorkingPath, \"CrashReport-\"+sCrashReportSource+\".log\"))\n",
        "\treturn nil\n",
        1,
    )
    text = text.replace(
        "func SetLocale(localeId string) error {\n"
        "\tif strings.Contains(localeId, \"@\") {\n"
        "\t\tlocaleId = strings.Split(localeId, \"@\")[0]\n"
        "\t}\n"
        "\tif !locale.Set(localeId) {\n"
        "\t\treturn E.New(\"unsupported locale: \", localeId)\n"
        "\t}\n"
        "\treturn nil\n"
        "}\n",
        "func SetLocale(localeId string) {\n"
        "\tlocale.Set(localeId)\n"
        "}\n",
        1,
    )
    for marker in [
        "\nfunc GoVersion() string {",
        "\nfunc FormatBitrate(bps int64) string {",
        "\nconst NetworkQualityDefaultConfigURL = networkquality.DefaultConfigURL",
    ]:
        if marker in text:
            start = text.index(marker)
            end = text.index("\nfunc ProxyDisplayType(proxyType string) string {", start)
            text = text[:start] + text[end:]
            break
    write("experimental/libbox/setup.go", text)


def patch_daemon() -> None:
    trim_imports(
        "daemon/started_service.go",
        [
            "unsafe",
            "github.com/sagernet/sing-box/common/dialer",
            "github.com/sagernet/sing-box/common/networkquality",
            "github.com/sagernet/sing-box/common/stun",
            "github.com/sagernet/sing-box/service/oomkiller",
            "google.golang.org/grpc/codes",
            "google.golang.org/grpc/status",
        ],
    )
    text = read("daemon/started_service.go")
    text = text.replace('\tC "github.com/sagernet/sing-box/constant"\n', "", 1)
    for start_marker, end_marker, replacement in [
        (
            "\nfunc (s *StartedService) TriggerDebugCrash(ctx context.Context, request *DebugCrashRequest) (*emptypb.Empty, error) {",
            "\nfunc (s *StartedService) SubscribeConnections(",
            "\nfunc (s *StartedService) TriggerDebugCrash(ctx context.Context, request *DebugCrashRequest) (*emptypb.Empty, error) {\n"
            "\treturn &emptypb.Empty{}, nil\n"
            "}\n"
            "\n"
            "func (s *StartedService) TriggerOOMReport(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {\n"
            "\treturn &emptypb.Empty{}, nil\n"
            "}\n",
        ),
        (
            "\nfunc resolveTailscaleEndpoint(instance *Instance, tag string) (adapter.Endpoint, error) {",
            "\nfunc (s *StartedService) mustEmbedUnimplementedStartedServiceServer() {",
            "\nfunc (s *StartedService) StartNetworkQualityTest(request *NetworkQualityTestRequest, server grpc.ServerStreamingServer[NetworkQualityTestProgress]) error {\n"
            "\treturn nil\n"
            "}\n"
            "\n"
            "func (s *StartedService) StartSTUNTest(request *STUNTestRequest, server grpc.ServerStreamingServer[STUNTestProgress]) error {\n"
            "\treturn nil\n"
            "}\n"
            "\n"
            "func (s *StartedService) SubscribeTailscaleStatus(_ *emptypb.Empty, server grpc.ServerStreamingServer[TailscaleStatusUpdate]) error {\n"
            "\treturn nil\n"
            "}\n"
            "\n"
            "func (s *StartedService) StartTailscalePing(request *TailscalePingRequest, server grpc.ServerStreamingServer[TailscalePingResponse]) error {\n"
            "\treturn nil\n"
            "}\n"
            "\n"
            "func (s *StartedService) SetTailscaleExitNode(ctx context.Context, request *SetTailscaleExitNodeRequest) (*emptypb.Empty, error) {\n"
            "\treturn &emptypb.Empty{}, nil\n"
            "}\n"
            "\n"
            "func (s *StartedService) TailscaleLogout(ctx context.Context, request *TailscaleLogoutRequest) (*emptypb.Empty, error) {\n"
            "\treturn &emptypb.Empty{}, nil\n"
            "}\n"
            "\n"
            "\nfunc (s *StartedService) StartTailscaleSSHSession(server grpc.BidiStreamingServer[TailscaleSSHClientMessage, TailscaleSSHServerMessage]) error {\n"
            "\treturn nil\n"
            "}\n",
        ),
    ]:
        start = text.index(start_marker)
        end = text.index(end_marker, start)
        text = text[:start] + replacement + text[end:]
    write("daemon/started_service.go", text)
    disable_go_file("daemon/started_service_tailscale_ssh.go")


def main() -> None:
    for path in [
        "experimental/libbox/command_types_nq.go",
        "experimental/libbox/command_types_stun.go",
        "experimental/libbox/command_types_tailscale.go",
        "experimental/libbox/command_types_tailscale_ping.go",
        "experimental/libbox/command_types_tailscale_ssh.go",
        "experimental/libbox/debug.go",
        "experimental/libbox/log.go",
        "experimental/libbox/networkquality.go",
        "experimental/libbox/stun.go",
        "experimental/libbox/ssh_shell.go",
        "experimental/libbox/native_shell_session.go",
        "experimental/libbox/native_shell_session_stub.go",
        "experimental/libbox/neighbor.go",
        "experimental/libbox/neighbor_darwin.go",
        "experimental/libbox/neighbor_linux.go",
        "experimental/libbox/neighbor_stub.go",
        "experimental/libbox/neighbor_unix.go",
        "experimental/libbox/oom_report.go",
        "experimental/libbox/report.go",
    ]:
        disable_go_file(path)
    patch_platform_interface()
    patch_service_wrapper()
    patch_config_stub()
    patch_command_client()
    patch_command_server()
    patch_setup()
    patch_daemon()


if __name__ == "__main__":
    main()
