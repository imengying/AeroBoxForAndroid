import hashlib
from pathlib import Path


ROOT = Path.cwd()
TEMPLATE_ROOT = Path(__file__).resolve().parent.parent / "libbox"
DISABLED_BUILD_TAG = "//go:build aerobox_disabled_libbox_feature\n\n"

UPSTREAM_HASHES = {
    "include/registry.go": "cbc7bc06391fe555828782df7bc1ce0844e446a82647448739dbb3e8e3eef19e",
    "include/quic.go": "a757f7fb9de40dd1d0da8b89d8605f7fe0eece9359e4c68ff8865a7ff7addc35",
    "experimental/libbox/build_info.go": "6d17d97083202147a1611344f724122e42a94cbda600d555cd57f895ef001a0a",
    "experimental/libbox/command.go": "0b209728b162f775dd664443004f4237279bd596c4b5f4ce5cc9cbca3cb85544",
    "experimental/libbox/command_client.go": "c679be375a238ea43acf31b957009fa6f49fd4b11753e0eb1f17ff86a2e8d8a0",
    "experimental/libbox/command_types.go": "e80beccb943767c7776be83f594256e612a237a98a148fcfca4679a339ea62a5",
    "experimental/libbox/deprecated.go": "d3eafe8092bb78276f88e1428ef02876a807d3d9ad5668afe192f776898f2629",
    "experimental/libbox/fdroid.go": "749c57b9a52eaf99a5fcb01a26d1028be10a73859422cadff3b531e18117196b",
    "experimental/libbox/fdroid_mirrors.go": "5a069edecf0766ab35d7dea57ca99dfe3c5307875304179f2767d57a11ca4ed3",
    "experimental/libbox/http.go": "ceacdd7722fbc70f7132eb27b18d98907b23e1dcf950a5e18cfe6742e1e3d447",
    "experimental/libbox/log.go": "ace67f3e6b3c4bc5d69814b1174ca688e76f75f8ad1155e732631a7dd747ab5f",
    "experimental/libbox/pprof.go": "8be57f35cedebcff7e325133ce162c2b602162e606362c4f42a1c4c6a12dd3d1",
    "experimental/libbox/profile_import.go": "df883b526a5f63c799d6713b90fa7d61927164788333bf603e423c0a9ba3c135",
    "experimental/libbox/remote_profile.go": "63b30392f33b8cd0d6787105d64a3787446aeefbe24cbb506756131d94d2f895",
    "experimental/libbox/semver.go": "dbcf34248eb9ad06fae1f5fca667045fcb1b0e4f5ea0de37dc5c62ddb7eb49b6",
    "experimental/libbox/semver_test.go": "dd0901f2b0ddfc7a4564d067c16f53dc90e11157a810ce2658940fb8de13f9d2",
    "experimental/libbox/platform.go": "b25817582c554d713f49d23267850d79893620862f55ffbc538e887422b6ea9e",
    "experimental/libbox/service.go": "6539b080a3db16ec4ba6150c1e445e8b2da57434be07a0b4de44d1bd97687c04",
    "experimental/libbox/config.go": "0f140bfa9897231be300263040c65f87c23167f31ca38dbc0a00c1fa8008d304",
    "experimental/libbox/command_server.go": "7c1bdad02ee81c397e56eb326994a2a75c435531afaeaf643d7c971446be344d",
    "experimental/libbox/setup.go": "688a3286ab733f2a94aa05a5259460519c86fe627b9126475f05cd67c5ee0512",
    "experimental/libbox/monitor.go": "cfbfe1e35ecebc375f35b3a44d165ec78c3c157228b3ed6c315a31f45cdf4c2f",
    "experimental/libbox/bridge_service_darwin.go": "74aeb9334cef49f231dc743c8e0eb021db65cf5fa7d0d2d927c0c5a40f6835cf",
    "experimental/libbox/bridge_service_linux.go": "615814c3ed53d0cbfa411c51c54e7fab040e8dba56d72b932f02a06f040ccb7c",
    "experimental/libbox/bridge_stub.go": "7bb780f47fadcbd57dd4ea0409294b42bc0011e8ea49fbed135add1eddae01bd",
    "experimental/libbox/command_client_remote.go": "382e6f6e7670624b81fd5540594b47dd7dba0b397a0aa1ed86ee4d84a6e8e03f",
    "experimental/libbox/command_types_nq.go": "423988c7861b6c4a144ce3e7edabcf774574b1c4578ad5425f201ee61907e679",
    "experimental/libbox/command_types_openconnect.go": "3e769f110222bbc615ea863d39ca6315dfcd7945a809f7a24247f3328a81bb4a",
    "experimental/libbox/command_types_openvpn.go": "9c862b97145d535488a1bbaa0d61c64d5bfcdc3daa3834013019f43ac21954ee",
    "experimental/libbox/command_types_stun.go": "0780448a9ce2d9c92c2049f69b6c9b0b99895dee6b14c31bd788211b31f0a149",
    "experimental/libbox/command_types_taildrop.go": "9c7ae5d615ea6bae42a7f812836537b987276f11230cae07b31953def744f3d2",
    "experimental/libbox/command_types_tailscale.go": "0d03a993229911701a23a9a9c32e7ec40ce811da75608f3872bd374b9af3a24b",
    "experimental/libbox/command_types_tailscale_ping.go": "5885585fbba031b2f9768f578a5d04beb9cd3461596d5664be60a0df987fdb24",
    "experimental/libbox/command_types_tailscale_ssh.go": "85a492691d15ddf0cb5e641366f0891e31967788e4bc47b7b2e3bb69c4a9eda2",
    "experimental/libbox/command_types_usbip.go": "606001d9876f80ba82f0e7d81e7744f14ec8f9a7daa9673f1daffbec06f0d48f",
    "experimental/libbox/command_types_usbip_local.go": "6726a91f5c07c6c76a849a30baa52623f99ae6efe1a623ae63166f375dd1df59",
    "experimental/libbox/command_types_usbip_local_darwin.go": "580e96383e9bb0a91facb0c2056674c05b8b3c002b46e392b331b357498c41a2",
    "experimental/libbox/command_types_usbip_local_stub.go": "35288ad29055c2af92de41d424ec42d833f6537615f9a80b203156cb7bcbacf2",
    "experimental/libbox/command_types_usbip_status.go": "8d9ea6279501922c3ffba823aa22757d1e40e85a6c4afc93ef95daa490286261",
    "experimental/libbox/debug.go": "1a4b4390441b6356048770110e06799bdaf5196f847ddbb60c45dbcf2828ebc1",
    "experimental/libbox/native_shell_session.go": "3a3702f787c48d5dde1f3ebcdc13c2d0c08693b65a2052499aff7422e86db723",
    "experimental/libbox/native_shell_session_stub.go": "1e5ee8dd0fb4dfbecfd7fa430a0e5eccd598fa73bddcf59d0f2922f11b84820c",
    "experimental/libbox/neighbor.go": "cfe24dd4252aba380233db1979bc786eda8e8499ca5c491be56c458a697bc33f",
    "experimental/libbox/neighbor_darwin.go": "5277b8288f401e376da569b419646cc689e35c6066b313b8e3ec6b166f51da59",
    "experimental/libbox/neighbor_linux.go": "40e33bce6550e87d21749c07b748699fcb7f3bf3febb0f3712aa7d636021bdb8",
    "experimental/libbox/neighbor_stub.go": "0f4b407df01d1c754335e340ff4c87539e38df60893c5cdbb8f51b08398174bc",
    "experimental/libbox/neighbor_unix.go": "9cda1d0d694bca72be0f345f7a9e8cee3bcc2e7b36735ca00803c8d7b9d0c73c",
    "experimental/libbox/networkquality.go": "6dc6e3b4baf8c03aeee235788abd9732fcb436ff2df9aad919628bc84cbf8588",
    "experimental/libbox/oom_report.go": "619ff7c12181600c721f65356a37f294c40e54b7933b58970b9329d0f9fbf581",
    "experimental/libbox/power_report.go": "52098d7c65096aa5b66e5c8adb0cc016ba597f095164f0f5fdbaf2ec1bff334f",
    "experimental/libbox/report.go": "b15bc07557f644afe2a903c136760441e75acc0956d448e8b656b0f4aadfff23",
    "experimental/libbox/ssh_shell.go": "67a29a74f2da51306625bf34891a21d89e0408729be732d2be4a91b54c6ae829",
    "experimental/libbox/stun.go": "f46eebc255678de7653126229d2b24378566d31a6e32c200ff097ab6cf1cb570",
}

DISABLED_LIBBOX_FILES = (
    "experimental/libbox/build_info.go",
    "experimental/libbox/command.go",
    "experimental/libbox/command_client.go",
    "experimental/libbox/command_client_remote.go",
    "experimental/libbox/command_types_nq.go",
    "experimental/libbox/command_types_openconnect.go",
    "experimental/libbox/command_types_openvpn.go",
    "experimental/libbox/command_types_stun.go",
    "experimental/libbox/command_types_taildrop.go",
    "experimental/libbox/command_types_tailscale.go",
    "experimental/libbox/command_types_tailscale_ping.go",
    "experimental/libbox/command_types_tailscale_ssh.go",
    "experimental/libbox/command_types_usbip.go",
    "experimental/libbox/command_types_usbip_local.go",
    "experimental/libbox/command_types_usbip_local_darwin.go",
    "experimental/libbox/command_types_usbip_local_stub.go",
    "experimental/libbox/command_types_usbip_status.go",
    "experimental/libbox/deprecated.go",
    "experimental/libbox/fdroid.go",
    "experimental/libbox/fdroid_mirrors.go",
    "experimental/libbox/http.go",
    "experimental/libbox/log.go",
    "experimental/libbox/pprof.go",
    "experimental/libbox/profile_import.go",
    "experimental/libbox/remote_profile.go",
    "experimental/libbox/semver.go",
    "experimental/libbox/semver_test.go",
    "experimental/libbox/bridge_service_darwin.go",
    "experimental/libbox/bridge_service_linux.go",
    "experimental/libbox/bridge_stub.go",
    "experimental/libbox/debug.go",
    "experimental/libbox/native_shell_session.go",
    "experimental/libbox/native_shell_session_stub.go",
    "experimental/libbox/neighbor.go",
    "experimental/libbox/neighbor_darwin.go",
    "experimental/libbox/neighbor_linux.go",
    "experimental/libbox/neighbor_stub.go",
    "experimental/libbox/neighbor_unix.go",
    "experimental/libbox/networkquality.go",
    "experimental/libbox/oom_report.go",
    "experimental/libbox/power_report.go",
    "experimental/libbox/report.go",
    "experimental/libbox/ssh_shell.go",
    "experimental/libbox/stun.go",
)


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


def verify_upstream_file(path: str) -> None:
    file_path = ROOT / path
    if not file_path.exists():
        raise SystemExit(f"{path}: file not found")
    actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
    expected = UPSTREAM_HASHES[path]
    if actual != expected:
        raise SystemExit(
            f"{path}: upstream file changed (expected {expected}, found {actual}); "
            "review the AeroBox slim patch before releasing"
        )


def disable_verified_go_file(path: str) -> None:
    verify_upstream_file(path)
    file_path = ROOT / path
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


def replace_with_template(path: str, template_name: str) -> None:
    verify_upstream_file(path)
    template_path = TEMPLATE_ROOT / template_name
    if not template_path.exists():
        raise SystemExit(f"{template_path}: template not found")
    write(path, template_path.read_text())


def patch_service_wrapper() -> None:
    path = "experimental/libbox/service.go"
    verify_upstream_file(path)
    remove_once(path, '\t"github.com/sagernet/sing-box/service/powerreport"\n')
    remove_once(path, "\tpowerManager           *powerreport.Manager\n")
    remove_once(path, "\toptions.InterfaceMonitor.RegisterMyInterface(options.Name)\n")
    remove_once(path, "\tw.iif.RegisterMyInterface(options.Name)\n")
    remove_once(
        path,
        "\t\t\tGateways: common.Filter(common.Map(iteratorToArray[string](netInterface.Gateway), func(it string) netip.Addr {\n"
        "\t\t\t\tgateway, _ := netip.ParseAddr(it)\n"
        "\t\t\t\treturn gateway.Unmap().WithZone(\"\")\n"
        "\t\t\t}), netip.Addr.IsValid),\n",
    )
    replace_once(
        path,
        "func (w *platformInterfaceWrapper) CancelNotification(identifier string, typeID int32) error {\n"
        "\treturn w.iif.CancelNotification(identifier, typeID)\n"
        "}\n",
        "func (w *platformInterfaceWrapper) CancelNotification(identifier string, typeID int32) error {\n"
        "\treturn nil\n"
        "}\n",
    )
    text = read(path)
    start = text.index("\nfunc (w *platformInterfaceWrapper) UsePlatformNeighborResolver() bool {")
    end = text.index("\nfunc AvailablePort(startPort int32) (int32, error) {", start)
    replacement = """
func (w *platformInterfaceWrapper) UsePlatformNeighborResolver() bool {
	return false
}

func (w *platformInterfaceWrapper) StartNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return E.New("platform neighbor resolver is not supported")
}

func (w *platformInterfaceWrapper) CloseNeighborMonitor(listener adapter.NeighborUpdateListener) error {
	return nil
}

func (w *platformInterfaceWrapper) UsePlatformShell() bool {
	return false
}

func (w *platformInterfaceWrapper) CheckPlatformShell() error {
	return nil
}

func (w *platformInterfaceWrapper) OpenShellSession(user *adapter.PlatformUser, command string, environ []string, term string, rows int32, cols int32) (adapter.ShellSession, error) {
	return nil, E.New("platform shell is not supported")
}

func (w *platformInterfaceWrapper) LookupSFTPServer() (string, error) {
	return "", E.New("platform shell is not supported")
}

func (w *platformInterfaceWrapper) ReadSystemSSHHostKey() ([]byte, error) {
	return nil, E.New("platform shell is not supported")
}

func (w *platformInterfaceWrapper) TailscaleHostname() string {
	return ""
}

func (w *platformInterfaceWrapper) LookupUser(username string) (*adapter.PlatformUser, error) {
	return nil, E.New("platform shell is not supported")
}

func (w *platformInterfaceWrapper) UsePlatformBridge() bool {
	return false
}

func (w *platformInterfaceWrapper) CreateBridge(options adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, E.New("platform bridge is not supported")
}
"""
    write(path, text[:start] + "\n" + replacement + text[end:])


def patch_config() -> None:
    path = "experimental/libbox/config.go"
    verify_upstream_file(path)
    remove_once(path, '\t"reflect"\n')
    remove_once(path, '\t"github.com/sagernet/sing-box/schema"\n')
    text = read(path)
    start = text.index("\nfunc GenerateConfigSchema() (*StringBox, error) {")
    end = text.index("\nfunc FormatConfig(configContent string) (*StringBox, error) {", start)
    write(path, text[:start] + text[end:])


def patch_monitor() -> None:
    path = "experimental/libbox/monitor.go"
    verify_upstream_file(path)
    remove_once(path, '\t"github.com/sagernet/sing-box/service/powerreport"\n')
    remove_once(
        path,
        "func (m *platformDefaultInterfaceMonitor) UpdateNetworkPath(networkPath string) {\n"
        "\tm.logger.Debug(\"updated network path: \", networkPath)\n"
        "\tif m.powerManager == nil {\n"
        "\t\treturn\n"
        "\t}\n"
        "\trecorder := m.powerManager.Recorder()\n"
        "\tif recorder == nil {\n"
        "\t\treturn\n"
        "\t}\n"
        "\trecorder.UpdateNetworkPath(networkPath)\n"
        "}\n\n",
    )
    remove_once(
        path,
        "\tvar recorder *powerreport.Recorder\n"
        "\tif m.powerManager != nil {\n"
        "\t\trecorder = m.powerManager.Recorder()\n"
        "\t}\n"
        "\tif recorder != nil {\n"
        "\t\tnetworkType := interfaceName\n"
        "\t\tif interfaceIndex32 == -1 {\n"
        "\t\t\tnetworkType = \"none\"\n"
        "\t\t} else {\n"
        "\t\t\tif isExpensive {\n"
        "\t\t\t\tnetworkType += \",expensive\"\n"
        "\t\t\t}\n"
        "\t\t\tif isConstrained {\n"
        "\t\t\t\tnetworkType += \",constrained\"\n"
        "\t\t\t}\n"
        "\t\t}\n"
        "\t\trecorder.UpdateNetworkType(networkType)\n"
        "\t}\n",
    )


def patch_command_server() -> None:
    path = "experimental/libbox/command_server.go"
    verify_upstream_file(path)
    remove_once(path, '\t"github.com/sagernet/sing-box/service/oomkiller"\n')
    remove_once(path, '\t"github.com/sagernet/sing-box/service/powerreport"\n')
    remove_once(path, "\tpowerManager      *powerreport.Manager\n")
    remove_once(path, "\toomRecorder       *oomkiller.Recorder\n")
    remove_once(path, "\tTriggerNativeCrash() error\n")
    remove_once(path, "\tConnectSSHAgent() (int32, error)\n")
    remove_once(
        path,
        "\tpowerManager := powerreport.NewManager()\n"
        "\tservice.MustRegister[*powerreport.Manager](ctx, powerManager)\n",
    )
    remove_once(path, "\t\tpowerManager: powerManager,\n")
    remove_once(path, "\t\tpowerManager:      powerManager,\n")
    remove_once(
        path,
        "\t\tOOMKillerEnabled:  sOOMKillerEnabled,\n"
        "\t\tOOMKillerDisabled: sOOMKillerDisabled,\n"
        "\t\tOOMMemoryLimit:    uint64(sOOMMemoryLimit),\n",
    )
    replace_once(
        path,
        "\toomRecorder := oomkiller.NewRecorder(OOMRecorderOptions(server.StartedService))\n"
        "\tservice.MustRegister[*oomkiller.Recorder](ctx, oomRecorder)\n"
        "\toomRecorder.Start()\n"
        "\tserver.oomRecorder = oomRecorder\n"
        "\tserver.managedService = daemon.NewManagedService(daemon.ManagedServiceOptions{\n"
        "\t\tHandler:     (*platformHandler)(server),\n"
        "\t\tDebug:       sDebug,\n"
        "\t\tOOMRecorder: oomRecorder,\n"
        "\t})\n"
        "\tif sPowerReportEnabled {\n"
        "\t\terr := powerManager.Start(PowerReportOptions(server.StartedService))\n"
        "\t\tif err != nil {\n"
        "\t\t\tlog.StdLogger().Error(E.Cause(err, \"start power report recorder\"))\n"
        "\t\t}\n"
        "\t}\n",
        "\tserver.managedService = daemon.NewManagedService(daemon.ManagedServiceOptions{\n"
        "\t\tHandler: (*platformHandler)(server),\n"
        "\t\tDebug:   sDebug,\n"
        "\t})\n",
    )
    remove_once(path, "\ts.powerManager.Close()\n")
    remove_once(path, "\ts.oomRecorder.Close()\n")
    remove_once(
        path,
        "\tsaveConfigSnapshot(configContent)\n"
        "\tif s.powerManager.Recorder() != nil {\n"
        "\t\tcopyConfigSnapshot(filepath.Join(sWorkingPath, powerreport.DraftDirectoryName))\n"
        "\t}\n",
    )
    for event in ("ne-sleep", "ne-wake"):
        remove_once(
            path,
            "\trecorder := s.powerManager.Recorder()\n"
            "\tif recorder != nil {\n"
            f"\t\trecorder.RecordPlatformEvent(\"{event}\")\n"
            "\t}\n",
        )
    replace_once(
        path,
        "func (h *platformHandler) TriggerNativeCrash() error {\n"
        "\treturn (*CommandServer)(h).handler.TriggerNativeCrash()\n"
        "}\n",
        "func (h *platformHandler) TriggerNativeCrash() error {\n"
        "\treturn os.ErrInvalid\n"
        "}\n",
    )
    replace_once(
        path,
        "func (h *platformHandler) ConnectSSHAgent() (int32, error) {\n"
        "\treturn (*CommandServer)(h).handler.ConnectSSHAgent()\n"
        "}\n",
        "func (h *platformHandler) ConnectSSHAgent() (int32, error) {\n"
        "\treturn -1, os.ErrInvalid\n"
        "}\n",
    )


def main() -> None:
    for path in DISABLED_LIBBOX_FILES:
        disable_verified_go_file(path)
    replace_with_template("experimental/libbox/command_types.go", "command_types.go")
    replace_with_template("experimental/libbox/platform.go", "platform.go")
    replace_with_template("experimental/libbox/setup.go", "setup.go")
    replace_with_template("include/registry.go", "registry.go")
    replace_with_template("include/quic.go", "quic.go")
    patch_service_wrapper()
    patch_config()
    patch_monitor()
    patch_command_server()


if __name__ == "__main__":
    main()
