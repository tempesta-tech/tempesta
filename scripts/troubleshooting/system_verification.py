#!/usr/bin/python3
"""
Command-line Interface to verify minimal OS and hardware requirements
"""

import argparse
import dataclasses
import json
import os
import subprocess
import socket

from typing import Optional


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


MINIMAL_RAM_MB = 8192
CPU_REQUIRED_FLAGS = {"sse4_2", "pse", "avx2", "bmi2", "adx"}
SUPPORTED_FILESYSTEMS = {"ext4", "btrfs", "xfs"}
ALLOWED_KERNEL_VERSIONS = {'5.10.35'}
EXPECTED_KERNEL_CONFIG_PARAMS = {
    "CONFIG_SLUB": {"y"},
    "CONFIG_HUGETLB_PAGE": {"y"},
    "CONFIG_SECURITY": {"y"},
    "CONFIG_SECURITY_NETWORK": {"y"},
    "CONFIG_SECURITY_TEMPESTA": {"y"},
    "CONFIG_DEFAULT_SECURITY_TEMPESTA": {"y"},
    "CONFIG_SOCK_CGROUP_DATA": {"y"},
    "CONFIG_NET": {"y"},
    "CONFIG_CGROUPS": {"y"},
    "CONFIG_CGROUP_NET_PRIO": {"y"},
    "CONFIG_NF_TABLES": {"m", "y"},
    "CONFIG_NF_TABLES_IPV4": {"y"},
    "CONFIG_NF_TABLES_IPV6": {"y"},
    "CONFIG_WATCHDOG": {"y"},
    "CONFIG_SOFTLOCKUP_DETECTOR": {"y"},
    "CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC": {"y"},
    "CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC_VALUE": {"1"},
    "CONFIG_HARDLOCKUP_DETECTOR_PERF": {"y"},
    "CONFIG_HARDLOCKUP_CHECK_TIMESTAMP": {"y"},
    "CONFIG_HARDLOCKUP_DETECTOR": {"y"},
    "CONFIG_BOOTPARAM_HARDLOCKUP_PANIC": {"y"},
    "CONFIG_BOOTPARAM_HARDLOCKUP_PANIC_VALUE": {"1"},
    "CONFIG_DETECT_HUNG_TASK": {"y"},
}
EXPECTED_SYSCTL_PARAMS = {
    "kernel.panic": {"1"},
    "kernel.panic_on_oops": {"1"},
    "kernel.panic_on_rcu_stall": {"1"},
    "kernel.softlockup_panic": {"1"},
}


class SystemVerificationError(Exception):
    pass


def run_in_shell(cmd: str) -> str:
    """
    Run command in a shell and return its output

    :param cmd: command to run
    :return: output of command
    """
    return subprocess.check_output(cmd, shell=True).decode()


def get_single_shell_value(cmd: str) -> str:
    """
    Run command in a shell and return its first line. Skip new line
    symbol if needed

    :param cmd: command to run
    :return: first output line of command
    """
    value, *_ = run_in_shell(cmd).splitlines()
    return value


@dataclasses.dataclass
class CommandLineArgs:
    troubleshooting_host: str
    troubleshooting_port: str
    troubleshooting_mac: str
    netconsole_host: str
    netconsole_port: str
    netconsole_network_interface: str

    @classmethod
    def parse_args(cls) -> 'CommandLineArgs':
        """
        Read command line arguments

        :return: key-value arguments
        """
        parser = argparse.ArgumentParser(
            description="Check if OS and Machine is suitable with minimal Tempesta requirements, start Netconsole",
            epilog='./system_verification.py -nh=192.168.0.100 -nni=eth0 -th=192.168.0.101 -tm=00:00:00:00:00:00',
            add_help=True
        )
        parser.add_argument(
            '-th', '--troubleshooting-host',
            type=str,
            help="Tempesta Troubeshooting Server host, example (192.168.0.101)",
        )
        parser.add_argument(
            '-tp', '--troubleshooting-port',
            type=str,
            default='5555',
            help="Tempesta Troubeshooting Server port, example (5555)",
        )
        parser.add_argument(
            '-tm', '--troubleshooting-mac',
            type=str,
            help="Tempesta Troubeshooting Server Mac Address, example (aa:bb:cc:dd:ee:ff)",
        )
        parser.add_argument(
            '-nh', '--netconsole-host',
            type=str,
            help="Netconsole host, example (192.168.0.100)",
        )
        parser.add_argument(
            '-np', '--netconsole-port',
            type=str,
            default='5555',
            help="Netconsole port, example (5555)"
        )
        parser.add_argument(
            '-nni', '--netconsole-network-interface',
            type=str,
            help="Netconsole network interface, example (eth0)",
        )
        return cls(**vars(parser.parse_args()))


@dataclasses.dataclass
class CPUInfo:
    """
    Describe CPU info from /proc/cpuinfo
    """
    processor: Optional[str]
    vendor_id: Optional[str]
    cpu_family: Optional[str]
    model: Optional[str]
    model_name: Optional[str]
    stepping: Optional[int]
    microcode: Optional[str]
    cpu_mhz: Optional[str]
    cache_size: Optional[str]
    physical_id: Optional[str]
    siblings: Optional[str]
    core_id: Optional[str]
    cpu_cores: Optional[str]
    apicid: Optional[str]
    initial_apicid: Optional[str]
    fpu: Optional[str]
    fpu_exception: Optional[str]
    cpuid_level: Optional[str]
    wp: Optional[str]
    flags: list[str]
    vmx_flags: list[str]
    bugs: list[str]
    bogomips: Optional[str]
    clflush_size: Optional[str]
    cache_alignment: Optional[str]
    address_sizes: Optional[str]
    power_management: Optional[str]

    @classmethod
    def parse(cls, text: str) -> "CPUInfo":
        """
        Parse CPU info from text

        :param text: text to parse
        :return: CPUInfo object
        """
        kwargs = {}

        for line in text.splitlines():
            key, value = line.lower().split(":")
            _key = key.strip().replace(" ", "_")
            _value = value.strip()
            kwargs[_key] = _value

        return cls(**kwargs)

    def __post_init__(self, *_, **__) -> None:
        """
        Cast some data types

        :return: None
        """
        self.flags = self.flags.split(" ")
        self.vmx_flags = self.vmx_flags.split(" ")
        self.bugs = self.bugs.split(" ")


@dataclasses.dataclass
class SystemInfo:
    """
    Aggregated system info
    """

    ram_kb: int
    filesystem: str
    cpu: list[CPUInfo]
    page_size: int
    kernels: set[str]
    current_kernel: str
    network_adapter_rss_capable: bool
    modules: set[str]

    @property
    def ram_mb(self) -> int:
        """
        Available RAM size in MB

        :return: size in MB
        """
        return int(self.ram_kb / 1024)

    @property
    def is_tfw_kernel_loaded(self) -> bool:
        """
        Verify if custom Tempesta kernel is loaded

        :return: true if current kernel is Tempesta kernel
        """
        return "tfw" in self.current_kernel

    @property
    def current_kernel_version(self) -> str:
        """
        Get the current kernel version

        :return: kernel version
        """
        return '.'.join(self.current_kernel.split('.')[:3])

    @property
    def page_size_kb(self) -> int:
        """
        The page size in KB

        :return: size in KB
        """
        return int(self.page_size / 1024)

    @property
    def path_to_kernel_config(self):
        """
        Path to kernel config based on kernel name

        :return: path to config
        """
        return f"/boot/config-{self.current_kernel}"

    @property
    def path_to_sysctl_config(self):
        """
        Path to sysctl config

        :return: path to config
        """
        return "/etc/sysctl.conf"

    @classmethod
    def load(cls) -> "SystemInfo":
        """
        Load all available system info

        :return: SystemInfo object
        """
        return cls(
            ram_kb=cls.__total_ram(),
            filesystem=cls.__current_filesystem(),
            cpu=cls.__list_cpu_info(),
            page_size=cls.__page_size(),
            kernels=cls.__list_all_linux_kernels(),
            current_kernel=cls.__current_linux_kernel(),
            network_adapter_rss_capable=cls.__is_network_adapter_rss_capable(),
            modules=cls.__get_modules(),
        )

    def dict(self) -> dict:
        """
        Serialize system info to dict suitable for json dump

        :return: System info dict
        """
        return {
            "ram_kb": self.ram_kb,
            "filesystem": self.filesystem,
            "page_size": self.page_size,
            "kernels": list(self.kernels),
            "current_kernel": self.current_kernel,
            "network_adapter_rss_capable": self.network_adapter_rss_capable,
            "modules": list(self.modules),
            'cpu': [dataclasses.asdict(cpu) for cpu in self.cpu],
        }

    @staticmethod
    def __list_all_linux_kernels() -> set[str]:
        """
        Get all linux kernels

        :return: set of kernel names
        """
        out = run_in_shell("dpkg --list | grep linux-image | awk '{print $2}'")
        return {
            kernel for kernel in out.splitlines() if kernel.startswith("linux-image")
        }

    @staticmethod
    def __current_linux_kernel() -> str:
        """
        Get current loaded kernel name

        :return: current kernel name
        """
        return get_single_shell_value("uname -r")

    @staticmethod
    def __is_linux_kernel_config_exists(kernel_name: str) -> bool:
        """
        Check if kernel config exists

        :param kernel_name: the kernel name
        :return: true if kernel config exists
        """
        return os.path.exists(f"/boot/config-{kernel_name}")

    @staticmethod
    def __list_cpu_info() -> list[CPUInfo]:
        """
        Get all available CPU info

        :return: list of available CPU info
        """
        data = run_in_shell("cat /proc/cpuinfo")
        cpus = data.strip().split("\n\n")
        return [CPUInfo.parse(cpu) for cpu in cpus]

    @staticmethod
    def __total_ram() -> int:
        """
        Get total RAM size in KB

        :return: RAM size in KB
        """
        data = get_single_shell_value("grep MemTotal /proc/meminfo | awk '{print $2}'")
        return int(data)

    @staticmethod
    def __current_filesystem() -> str:
        """
        Get current filesystem name

        :return: filesystem name
        """
        return get_single_shell_value("df -T / | awk 'NR==2{print $2}'")

    @staticmethod
    def __page_size() -> int:
        """
        Get page size in bytes

        :return: page size
        """
        return int(get_single_shell_value("getconf PAGE_SIZE"))

    @staticmethod
    def __get_modules() -> set[str]:
        """
        Get all loaded system modules

        :return: set of loaded system modules
        """
        return set(run_in_shell("lsmod | awk '{print $1}'").strip().split("\n"))

    @staticmethod
    def __is_network_adapter_rss_capable() -> bool:
        """
        Check if rss capable network adapter exists

        :return: true if network adapter exists
        """
        return (
            int(
                get_single_shell_value(
                    "ls /sys/class/net/**/queues | grep 'rx-' | wc -l"
                )
            )
            > 0
        )


@dataclasses.dataclass
class Config:
    """
    Common config validator for `key=value` configs
    """
    path: str
    vars: dict[str, str] = None

    def __post_init__(self):
        """
        Load config
        """
        self.vars = {}

        if not os.path.isfile(self.path):
            raise SystemVerificationError(
                "Can not load configuration file. " f"`{self.path}` does not exist"
            )

        with open(self.path, "r") as f:
            for line in f.readlines():
                line = line.strip().lower()

                if line.startswith("#"):
                    continue

                if "=" not in line:
                    continue

                key, value = line.split("=")
                key = key.strip()
                value = value.strip()

                self.vars[key] = value

    def check_params_are_same(
        self, params: dict[str, set[str]], errors: list = None
    ) -> bool:
        """
        Verify if provided params are same as installed in config

        :param params: dictionary with config key-value pairs
        :param errors: text error messages accumulator
        :return: true is the same
        """
        if errors is None:
            errors = []

        for key, value in params.items():
            lower_key = key.lower()

            if lower_key not in self.vars:
                if Optional in value:
                    continue

                errors.append(f"`{key}={value}` is not defined.")
                continue

            if self.vars[lower_key] not in value:
                formatted_value = '/'.join(value)
                errors.append(
                    f"`{key}={self.vars[lower_key]}` has different value, should be `{key}={formatted_value}`"
                )
                continue

        return len(errors) == 0

    def dict(self) -> dict:
        """
        Export config key-value pairs as dictionary suitable for json dump

        :return: dict with config key-value pairs
        """
        return dataclasses.asdict(self)


def is_system_suitable(system_info: SystemInfo, errors: list = None) -> bool:
    """
    Make verification of system_info params with app limits

    :param system_info: loaded SystemInfo
    :param errors: text error messages accumulator
    :return: true if system is suitable
    """
    if errors is None:
        errors = []

    if not system_info.is_tfw_kernel_loaded:
        errors.append(
            f"Current loaded kernel is not suitable with TFW: "
            f"{system_info.current_kernel}"
        )

    if system_info.current_kernel_version not in ALLOWED_KERNEL_VERSIONS:
        errors.append(
            f"Current loaded kernel has not suitable version: {system_info.current_kernel_version}, "
            f"supported versions {system_info.current_kernel}"
        )

    not_supported_flags = CPU_REQUIRED_FLAGS - set(system_info.cpu[0].flags)

    if not_supported_flags:
        errors.append(
            "Your processor does not support minimal requirement to run Tempesta:"
            f" {not_supported_flags} are unsupported."
        )

    if system_info.ram_mb < MINIMAL_RAM_MB:
        errors.append(
            f"The minimal amount of RAM required by Tempesta is {MINIMAL_RAM_MB} MB"
            f", but you have {system_info.ram_mb} MB"
        )

    if system_info.filesystem not in SUPPORTED_FILESYSTEMS:
        errors.append(
            f"TFW supports only {', '.join(SUPPORTED_FILESYSTEMS)}"
            f", but you have {system_info.filesystem} "
        )

    if not system_info.network_adapter_rss_capable:
        errors.append("RSS capability is not supported by network adapter")

    return len(errors) == 0


def print_kernel_log(text: str):
    """
    Write text to the kernel log

    :param text: text to wrote
    :return:
    """
    with open('/dev/kmsg', 'w') as f:
        f.write(f'[tempesta sc] {text}')


def tempesta_log(text):
    """
    Write text to the kernel log and stdout

    :param text: text to write
    :return:
    """
    print_kernel_log(text)
    print(text)


def format_errors(description: str, errors: list[str]) -> None:
    """
    Pretty print error messages and add some extra description

    :param description: description of errors group
    :param errors: list of text errors
    :return: None
    """
    tempesta_log(f"{description}/ (Total {len(errors)} errors)")

    for index, error in enumerate(errors):
        tempesta_log(f"\t{index + 1}. {error}")


def setup_netconsole(
    src_host: str,
    src_port: int,
    src_eth_interface: str,
    dst_host: str,
    dst_port: int,
    dst_mac: str,
    errors: list = None,
) -> bool:
    """
    Setup Netconsole autostart with OS and turn in on immediately if possible

    :param src_host: netconsole host
    :param src_port: netconsole port
    :param src_eth_interface: netconsole network interface
    :param dst_host: system messages receiver host
    :param dst_port: system messages receiver port
    :param dst_mac: system messages receiver mac-address
    :param errors: error messages accumulator

    :return: true if netconsole prepared and activated
    """
    if errors is None:
        errors = []

    modules_dir = "/etc/modprobe.d"
    netconsole_module = f"{modules_dir}/netconsole.conf"
    netconsole_command = (
        f"netconsole={src_port}@{src_host}/{src_eth_interface},"
        f"{dst_port}@{dst_host}/{dst_mac}"
    )

    try:
        if not os.path.exists(modules_dir):
            os.makedirs(netconsole_module)

        with open(netconsole_module, "w") as f:
            f.write(f"options netconsole {netconsole_command}")
    except PermissionError:
        errors.append(f"Does not have permission to edit {netconsole_module}")
        return False

    subprocess.check_output(f"modprobe netconsole {netconsole_command}", shell=True)
    is_netconsole_running = (
        get_single_shell_value("lsmod | grep netconsole | wc -l") == "1"
    )

    if not is_netconsole_running:
        errors.append(
            "Netconsole was not activated. Please, check `dmesg | grep netconsole` for more info"
        )

    return len(errors) == 0


def send_system_info(
        support_host: str,
        support_port: int,
        system_info: str,
        errors: list = None
) -> bool:
    """
    Send system info to Tempesta Troubleshooting Server

    :param support_host: Tempesta Troubleshooting Server host
    :param support_port: Tempesta Troubleshooting Server port
    :param system_info: json serialized SystemInfo object

    :return: True if system info was sent
    """
    if errors is None:
        errors = []

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((support_host, support_port))
        sock.sendall(f"<sys-info>{system_info}</sys-info>".encode())
        return True
    except socket.timeout:
        errors.append('Could not connect to Tempesta Troubleshooting Server. Timeout.')

    except socket.gaierror:
        errors.append('Provided ip is invalid')

    except Exception as e:
        errors.append(str(e))

    return False


if __name__ == '__main__':
    args = CommandLineArgs.parse_args()
    info = SystemInfo.load()

    system_errors = []
    system_check_ok = is_system_suitable(system_info=info, errors=system_errors)

    if not system_check_ok:
        format_errors(
            description="OS configuration or hardware is not suitable", errors=system_errors
        )

    kernel_params_errors = []
    kernel_config = Config(path=info.path_to_kernel_config)
    kernel_config_ok = kernel_config.check_params_are_same(
        params=EXPECTED_KERNEL_CONFIG_PARAMS,
        errors=kernel_params_errors,
    )

    if not kernel_config_ok:
        format_errors(
            description=(
                "Kernel config params are missing or have different values."
                f" Please, check configuration of `{info.path_to_kernel_config}`"
            ),
            errors=kernel_params_errors,
        )

    sysctl_params_errors = []
    sysctl_config = Config(path=info.path_to_sysctl_config)
    sysctl_config_ok = sysctl_config.check_params_are_same(
        params=EXPECTED_SYSCTL_PARAMS,
        errors=sysctl_params_errors,
    )

    if not sysctl_config_ok:
        format_errors(
            description=(
                "Sysctl config params are missing or have different values."
                f" Please, check configuration of `{info.path_to_sysctl_config}`"
            ),
            errors=sysctl_params_errors,
        )

    verification_passed = all({system_check_ok, kernel_config_ok, sysctl_config_ok})

    if verification_passed:
        tempesta_log('Verification passed successfully!')

    else:
        tempesta_log('Verification passed with errors!')

    if not all([
        args.netconsole_host,
        args.netconsole_port,
        args.netconsole_network_interface,
        args.troubleshooting_port,
        args.troubleshooting_host,
    ]):
        tempesta_log('Skipped Netconsole configuration and Support Server connection')
        exit(0)

    netconsole_errors = []
    netconsole_activated = setup_netconsole(
        src_host=args.netconsole_host,
        src_port=int(args.netconsole_port),
        src_eth_interface=args.netconsole_network_interface,
        dst_host=args.troubleshooting_host,
        dst_port=int(args.troubleshooting_port),
        dst_mac=args.troubleshooting_mac,
        errors=netconsole_errors,
    )

    if not netconsole_activated:
        format_errors(
            description="Errors while Netconsole configuring", errors=netconsole_errors
        )

    tempesta_log('Netconsole activated')

    troubleshooting_server_errors = []
    is_sent = send_system_info(
        support_host=args.troubleshooting_host,
        support_port=int(args.troubleshooting_port),
        system_info=json.dumps(
            {
                "sys_info": info.dict(),
                "kernel_config": kernel_config.dict(),
                "sysctl_config": sysctl_config.dict(),
            }
        ),
        errors=troubleshooting_server_errors,
    )

    if not is_sent:
        format_errors(
            description="Connection to Tempesta Troubleshooting Server", errors=troubleshooting_server_errors
        )
