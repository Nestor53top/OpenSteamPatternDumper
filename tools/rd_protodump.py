#!/usr/bin/env python3
"""
RD.py — Runtime Dump of Steam Protobuf Definitions
====================================================

Автоматически находит Steam, запускает его, дампит все .proto файлы
из памяти запущенного процесса.

Использование:
    python RD.py                    # Автоматически найдёт и запустит Steam
    python RD.py --output ./protos  # Указать папку вывода
    python RD.py --no-launch        # Не запускать Steam, только дампить если уже запущен
    python RD.py --pid 1234         # Дампить конкретный процесс
    python RD.py --verbose          # Подробный вывод
    python RD.py --watch            # Режим мониторинга (обновлять при изменениях)

Требования:
    pip install psutil pymem

Windows: запускать от администратора для доступа к памяти процессов
Linux:   запускать от root или с CAP_SYS_PTRACE
"""

import sys
import os
import time
import struct
import signal
import hashlib
import logging
import argparse
import subprocess
import threading
import platform
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

# ===================== Конфигурация =====================

__version__ = "1.0.0"
__author__ = "RD.py — Steam Protobuf Runtime Dumper"

# Логирование
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
DATE_FORMAT = '%H:%M:%S'

# Константы парсинга protobuf
WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_START_GROUP = 3
WIRE_END_GROUP = 4
WIRE_32BIT = 5

# FileDescriptorProto field numbers
FD_NAME = 1
FD_PACKAGE = 2
FD_DEPENDENCY = 3
FD_PUBLIC_DEPENDENCY = 4
FD_WEAK_DEPENDENCY = 5
FD_MESSAGE_TYPE = 6
FD_ENUM_TYPE = 7
FD_SERVICE = 8
FD_EXTENSION = 9
FD_OPTIONS = 10
FD_SOURCE_CODE_INFO = 11
FD_SYNTAX = 12

# DescriptorProto field numbers
DP_NAME = 1
DP_FIELD = 2
DP_EXTENSION = 3
DP_NESTED_TYPE = 4
DP_ENUM_TYPE = 5
DP_EXTENSION_RANGE = 6
DP_ONEOF_DECL = 7

# FieldDescriptorProto field numbers
FDP_NAME = 1
FDP_NUMBER = 3
FDP_LABEL = 4
FDP_TYPE = 5
FDP_TYPE_NAME = 6
FDP_DEFAULT_VALUE = 7
FDP_OPTIONS = 8
FDP_JSON_NAME = 10
FDP_PROTO3_OPTIONAL = 17

# Маппинги
TYPE_MAP = {
    1: "double", 2: "float", 3: "int64", 4: "uint64",
    5: "int32", 6: "fixed64", 7: "fixed32", 8: "bool",
    9: "string", 10: "group", 11: "message", 12: "bytes",
    13: "uint32", 14: "enum", 15: "sfixed32", 16: "sfixed64",
    17: "sint32", 18: "sint64",
}

LABEL_MAP = {
    1: "optional",
    2: "required",
    3: "repeated",
}

# Известные Steam процессы
STEAM_PROCESSES = [
    "steam.exe",
    "steamclient64.dll",
    "steamclient.dll",
    "SteamUI.dll",
    "GameOverlayRenderer64.dll",
    "GameOverlayRenderer.dll",
]

# Паттерны поиска Steam
STEAM_PATHS_WINDOWS = [
    r"C:\Program Files (x86)\Steam",
    r"C:\Program Files\Steam",
    r"D:\Steam",
    r"D:\Program Files (x86)\Steam",
    r"E:\Steam",
    r"E:\Program Files (x86)\Steam",
    r"F:\Steam",
]

STEAM_PATHS_LINUX = [
    "~/.steam/steam",
    "~/.local/share/Steam",
    "~/.steam/debian-installation",
    "/usr/share/steam",
    "/opt/steam",
]

# ===================== Логирование =====================

logger = logging.getLogger("RD")


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    logger.addHandler(handler)
    logger.setLevel(level)


# ===================== Protobuf Parser =====================

@dataclass
class ProtoField:
    """Одно поле protobuf"""
    number: int = 0
    wire_type: int = 0
    data: bytes = b''
    varint_value: int = 0


@dataclass
class ParsedMessage:
    """Распарсированное protobuf сообщение"""
    fields: Dict[int, List[ProtoField]] = field(default_factory=lambda: defaultdict(list))

    def get_varint(self, field_num: int, default: int = 0) -> int:
        fields = self.fields.get(field_num, [])
        if fields:
            return fields[0].varint_value
        return default

    def get_bytes(self, field_num: int) -> bytes:
        fields = self.fields.get(field_num, [])
        if fields:
            return fields[0].data
        return b''

    def get_string(self, field_num: int) -> str:
        return self.get_bytes(field_num).decode('utf-8', errors='replace')

    def get_messages(self, field_num: int) -> List['ParsedMessage']:
        result = []
        for f in self.fields.get(field_num, []):
            sub = parse_protobuf(f.data)
            if sub is not None:
                result.append(sub)
        return result

    def get_sub_message(self, field_num: int) -> Optional['ParsedMessage']:
        msgs = self.get_messages(field_num)
        return msgs[0] if msgs else None


def read_varint(data: bytes, offset: int) -> Tuple[int, int]:
    """Читает varint из данных"""
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if (byte & 0x80) == 0:
            return result, offset
        shift += 7
    return result, offset


def parse_protobuf(data: bytes) -> Optional[ParsedMessage]:
    """Парсит raw protobuf binary data"""
    if not data or len(data) == 0:
        return None

    msg = ParsedMessage()
    offset = 0

    while offset < len(data):
        try:
            tag, offset = read_varint(data, offset)
            if tag == 0 and offset >= len(data):
                break
            field_num = tag >> 3
            wire_type = tag & 0x07

            if field_num == 0 or wire_type > 5:
                break

            field = ProtoField(number=field_num, wire_type=wire_type)

            if wire_type == WIRE_VARINT:
                field.varint_value, offset = read_varint(data, offset)
            elif wire_type == WIRE_64BIT:
                if offset + 8 > len(data):
                    break
                field.varint_value = struct.unpack('<Q', data[offset:offset + 8])[0]
                field.data = data[offset:offset + 8]
                offset += 8
            elif wire_type == WIRE_LENGTH_DELIMITED:
                length, offset = read_varint(data, offset)
                if offset + length > len(data):
                    break
                field.data = data[offset:offset + length]
                offset += length
            elif wire_type == WIRE_32BIT:
                if offset + 4 > len(data):
                    break
                field.varint_value = struct.unpack('<I', data[offset:offset + 4])[0]
                field.data = data[offset:offset + 4]
                offset += 4
            elif wire_type in (WIRE_START_GROUP, WIRE_END_GROUP):
                continue
            else:
                break

            msg.fields[field_num].append(field)
        except Exception:
            break

    return msg if msg.fields else None


def find_valid_end(data: bytes) -> int:
    """Находит валидный конец protobuf дескриптора"""
    offset = 0
    last_valid = 0
    while offset < len(data):
        try:
            tag, off = read_varint(data, offset)
            fn = tag >> 3
            wt = tag & 7
            if fn == 0 or fn > 12 or wt > 5:
                return last_valid
            if wt == 0:
                _, off = read_varint(data, off)
            elif wt == 2:
                length, off = read_varint(data, off)
                if off + length > len(data):
                    return last_valid
                off += length
            elif wt == 5:
                off += 4
            elif wt == 1:
                off += 8
            else:
                return last_valid
            last_valid = off
            offset = off
        except Exception:
            return last_valid
    return last_valid


# ===================== Proto Converter =====================

class ProtoConverter:
    """Конвертирует binary protobuf descriptors в .proto текст"""

    def __init__(self):
        self.type_map = TYPE_MAP.copy()
        self.label_map = LABEL_MAP.copy()

    def decode_field(self, data: bytes) -> str:
        """Декодирует FieldDescriptorProto"""
        msg = parse_protobuf(data)
        if not msg:
            return ""

        name = msg.get_string(FDP_NAME)
        number = msg.get_varint(FDP_NUMBER)
        label = msg.get_varint(FDP_LABEL)
        type_id = msg.get_varint(FDP_TYPE)
        type_name = msg.get_string(FDP_TYPE_NAME)

        if not name or not number:
            return ""

        type_str = self.type_map.get(type_id, f"type{type_id}")
        if type_id in (11, 14) and type_name:
            type_str = type_name.lstrip('.')

        label_str = self.label_map.get(label, "")
        parts = []
        if label_str:
            parts.append(label_str)
        parts.append(type_str)
        parts.append(name)
        parts.append(f"= {number}")

        # Proto3 optional
        if msg.get_varint(FDP_PROTO3_OPTIONAL):
            parts.append("[optional = true]")

        return f"  {' '.join(parts)};"

    def decode_message(self, data: bytes, indent: int = 0) -> str:
        """Декодирует DescriptorProto"""
        msg = parse_protobuf(data)
        if not msg:
            return ""

        name = msg.get_string(DP_NAME)
        prefix = "  " * indent
        lines = [f"{prefix}message {name} {{"]

        # Поля
        for field_data in msg.fields.get(DP_FIELD, []):
            field_str = self.decode_field(field_data.data)
            if field_str:
                lines.append(field_str)

        # Вложенные сообщения
        for nested_data in msg.fields.get(DP_NESTED_TYPE, []):
            nested = self.decode_message(nested_data.data, indent + 1)
            if nested:
                lines.append(nested)

        # Enum
        for enum_data in msg.fields.get(DP_ENUM_TYPE, []):
            enum_str = self.decode_enum(enum_data.data, indent + 1)
            if enum_str:
                lines.append(enum_str)

        lines.append(f"{prefix}}}")
        return "\n".join(lines)

    def decode_enum(self, data: bytes, indent: int = 0) -> str:
        """Декодирует EnumDescriptorProto"""
        msg = parse_protobuf(data)
        if not msg:
            return ""

        name = msg.get_string(1)  # name
        prefix = "  " * indent
        lines = [f"{prefix}enum {name} {{"]

        # Values
        for val_data in msg.fields.get(2, []):  # value
            val_msg = parse_protobuf(val_data.data)
            if val_msg:
                val_name = val_msg.get_string(1)  # name
                val_num = val_msg.get_varint(2)    # number
                if val_name:
                    lines.append(f"{prefix}  {val_name} = {val_num};")

        lines.append(f"{prefix}}}")
        return "\n".join(lines)

    def decode_service(self, data: bytes, indent: int = 0) -> str:
        """Декодирует ServiceDescriptorProto"""
        msg = parse_protobuf(data)
        if not msg:
            return ""

        name = msg.get_string(1)  # name
        prefix = "  " * indent
        lines = [f"{prefix}service {name} {{"]

        # Methods
        for method_data in msg.fields.get(2, []):  # method
            method_msg = parse_protobuf(method_data.data)
            if method_msg:
                method_name = method_msg.get_string(1)   # name
                input_type = method_msg.get_string(2).lstrip('.')   # input_type
                output_type = method_msg.get_string(3).lstrip('.')  # output_type
                client_stream = method_msg.get_varint(5)
                server_stream = method_msg.get_varint(6)

                cs = "stream " if client_stream else ""
                ss = " stream" if server_stream else ""
                lines.append(f"{prefix}  rpc {method_name}({cs}{input_type}) returns ({output_type}{ss});")

        lines.append(f"{prefix}}}")
        return "\n".join(lines)

    def convert_file_descriptor(self, data: bytes) -> Tuple[str, str]:
        """Конвертирует FileDescriptorProto в .proto текст"""
        # Находим валидный конец
        end = find_valid_end(data)
        data = data[:end]

        msg = parse_protobuf(data)
        if not msg:
            return "", ""

        name = msg.get_string(FD_NAME)
        if not name:
            return "", ""

        package = msg.get_string(FD_PACKAGE)
        syntax = msg.get_string(FD_SYNTAX)

        lines = []

        # Syntax
        if syntax:
            lines.append(f'syntax = "{syntax}";')
        else:
            lines.append('syntax = "proto2";')

        # Package
        if package:
            lines.append(f"package {package};")
            lines.append("")

        # Dependencies
        for dep_data in msg.fields.get(FD_DEPENDENCY, []):
            dep = dep_data.data.decode('utf-8', errors='replace')
            lines.append(f'import "{dep}";')
        if FD_DEPENDENCY in msg.fields:
            lines.append("")

        # Messages
        for msg_data in msg.fields.get(FD_MESSAGE_TYPE, []):
            msg_text = self.decode_message(msg_data.data)
            if msg_text:
                lines.append(msg_text)
                lines.append("")

        # Enums
        for enum_data in msg.fields.get(FD_ENUM_TYPE, []):
            enum_text = self.decode_enum(enum_data.data)
            if enum_text:
                lines.append(enum_text)
                lines.append("")

        # Services
        for svc_data in msg.fields.get(FD_SERVICE, []):
            svc_text = self.decode_service(svc_data.data)
            if svc_text:
                lines.append(svc_text)
                lines.append("")

        text = "\n".join(lines).rstrip() + "\n"
        return name, text


# ===================== Platform-Specific Memory Access =====================

class MemoryReader:
    """Чтение памяти процесса (кроссплатформенное)"""

    def __init__(self, pid: int):
        self.pid = pid
        self.platform = platform.system().lower()
        self.handle = None
        self._setup()

    def _setup(self):
        """Инициализация чтения памяти"""
        if self.platform == "windows":
            self._setup_windows()
        elif self.platform == "linux":
            self._setup_linux()
        else:
            raise OSError(f"Unsupported platform: {self.platform}")

    def _setup_windows(self):
        """Windows: используем pymem или ctypes"""
        try:
            import pymem
            import pymem.process
            self.pm = pymem.Pymem(self.pid)
            self.handle = self.pm.process_handle
            logger.debug(f"Windows: Attached via pymem to PID {self.pid}")
        except ImportError:
            logger.warning("pymem не установлен, пробуем ctypes...")
            self._setup_windows_ctypes()

    def _setup_windows_ctypes(self):
        """Windows fallback: ctypes + Win32 API"""
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400

        self.handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            self.pid
        )

        if not self.handle:
            raise OSError(f"Cannot open process {self.pid}: {ctypes.get_last_error()}")

        # Структуры для VirtualQueryEx
        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        self.MBI = MEMORY_BASIC_INFORMATION
        self.kernel32 = kernel32
        self.ctypes = ctypes
        logger.debug(f"Windows: Attached via ctypes to PID {self.pid}")

    def _setup_linux(self):
        """Linux: /proc/pid/mem"""
        self.mem_path = f"/proc/{self.pid}/mem"
        if not os.path.exists(self.mem_path):
            raise OSError(f"Cannot access {self.mem_path}")

        # Читаем maps для определения регионов
        maps_path = f"/proc/{self.pid}/maps"
        self.regions = []
        with open(maps_path, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    addr_range = parts[0].split('-')
                    if len(addr_range) == 2:
                        try:
                            start = int(addr_range[0], 16)
                            end = int(addr_range[1], 16)
                            self.regions.append((start, end))
                        except ValueError:
                            continue

        logger.debug(f"Linux: Found {len(self.regions)} memory regions for PID {self.pid}")

    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """Читает блок памяти из процесса"""
        if self.platform == "windows":
            return self._read_windows(address, size)
        elif self.platform == "linux":
            return self._read_linux(address, size)
        return None

    def _read_windows(self, address: int, size: int) -> Optional[bytes]:
        """Чтение памяти на Windows"""
        try:
            if hasattr(self, 'pm'):
                return self.pm.read_bytes(address, size)
            else:
                return self._read_windows_ctypes(address, size)
        except Exception as e:
            logger.debug(f"Read failed at 0x{address:X}: {e}")
            return None

    def _read_windows_ctypes(self, address: int, size: int) -> Optional[bytes]:
        """Чтение памяти через ctypes"""
        try:
            buffer = self.ctypes.create_string_buffer(size)
            bytes_read = self.ctypes.c_size_t(0)

            result = self.kernel32.ReadProcessMemory(
                self.handle,
                self.ctypes.c_void_p(address),
                buffer,
                size,
                self.ctypes.byref(bytes_read)
            )

            if result:
                return buffer.raw[:bytes_read.value]
            return None
        except Exception:
            return None

    def _read_linux(self, address: int, size: int) -> Optional[bytes]:
        """Чтение памяти на Linux"""
        try:
            with open(self.mem_path, 'rb') as f:
                f.seek(address)
                return f.read(size)
        except (OSError, ValueError):
            return None

    def enumerate_modules(self) -> List[Tuple[str, int, int]]:
        """Возвращает список загруженных модулей (name, base, size)"""
        if self.platform == "windows":
            return self._enum_modules_windows()
        elif self.platform == "linux":
            return self._enum_modules_linux()
        return []

    def _enum_modules_windows(self) -> List[Tuple[str, int, int]]:
        """Windows: список модулей через pymem/ctypes"""
        try:
            if hasattr(self, 'pm'):
                import pymem.process
                modules = []
                for module in self.pm.list_modules():
                    modules.append((module.name, module.lpBaseOfDll, module.SizeOfImage))
                return modules
            else:
                return self._enum_modules_windows_ctypes()
        except Exception as e:
            logger.debug(f"Module enumeration failed: {e}")
            return []

    def _enum_modules_windows_ctypes(self) -> List[Tuple[str, int, int]]:
        """Windows: список модулей через ctypes"""
        import ctypes
        from ctypes import wintypes, Structure, POINTER, byref, c_char, c_void_p, c_ulong

        class MODULEINFO(Structure):
            _fields_ = [
                ("lpBaseOfDll", c_void_p),
                ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", c_void_p),
            ]

        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi

        modules = (wintypes.HMODULE * 1024)()
        cb_needed = wintypes.DWORD(0)

        if psapi.EnumProcessModules(self.handle, modules, ctypes.sizeof(modules), byref(cb_needed)):
            count = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
            result = []

            for i in range(count):
                name_buf = ctypes.create_string_buffer(256)
                psapi.GetModuleBaseNameA(self.handle, modules[i], name_buf, 256)

                mi = MODULEINFO()
                psapi.GetModuleInformation(self.handle, modules[i], byref(mi), ctypes.sizeof(mi))

                name = name_buf.value.decode('utf-8', errors='replace')
                result.append((name, mi.lpBaseOfDll, mi.SizeOfImage))

            return result
        return []

    def _enum_modules_linux(self) -> List[Tuple[str, int, int]]:
        """Linux: список модулей из /proc/pid/maps"""
        modules = []
        maps_path = f"/proc/{self.pid}/maps"

        try:
            with open(maps_path, 'r') as f:
                current_module = None
                current_start = 0

                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        addr_range = parts[0].split('-')
                        if len(addr_range) == 2:
                            start = int(addr_range[0], 16)
                            end = int(addr_range[1], 16)
                            path = parts[5]

                            if path and os.path.exists(path):
                                if path != current_module:
                                    if current_module:
                                        modules.append((current_module, current_start, start - current_start))
                                    current_module = path
                                    current_start = start

                if current_module:
                    modules.append((current_module, current_start, end - current_start))

        except Exception as e:
            logger.debug(f"Linux module enumeration failed: {e}")

        return modules

    def close(self):
        """Закрывает handle"""
        if self.platform == "windows" and self.handle:
            try:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(self.handle)
            except Exception:
                pass


# ===================== Proto Scanner =====================

class ProtoScanner:
    """Сканер protobuf дескрипторов в памяти процесса"""

    # Известные имена Steam proto файлов
    STEAM_PROTO_NAMES = [
        "steammessages_base.proto",
        "steammessages_auth.steamclient.proto",
        "steammessages_clientserver.proto",
        "steammessages_clientserver_2.proto",
        "steammessages_player.steamclient.proto",
        "steammessages_store.steamclient.proto",
        "steammessages_cloud.steamclient.proto",
        "steammessages_community.steamclient.proto",
        "steammessages_friends.steamclient.proto",
        "steammessages_gamenotifications.steamclient.proto",
        "steammessages_gameservers.steamclient.proto",
        "steammessages_credentials.steamclient.proto",
        "steammessages_depotbuilder.steamclient.proto",
        "steammessages_deviceauth.steamclient.proto",
        "steammessages_econ.steamclient.proto",
        "steammessages_inventory.steamclient.proto",
        "steammessages_linkfilter.steamclient.proto",
        "steammessages_offline.steamclient.proto",
        "steammessages_parental.steamclient.proto",
        "steammessages_partnerapps.steamclient.proto",
        "steammessages_physicalgoods.steamclient.proto",
        "steammessages_publishedfile.steamclient.proto",
        "steammessages_remoteclient.proto",
        "steammessages_remoteclient_discovery.proto",
        "steammessages_secrets.steamclient.proto",
        "steammessages_twofactor.steamclient.proto",
        "steammessages_unified_base.steamclient.proto",
        "steammessages_unified_test.steamclient.proto",
        "steammessages_video.steamclient.proto",
        "steammessages_broadcast.steamclient.proto",
        "steammessages_hiddevices.proto",
        "encrypted_app_ticket.proto",
        "content_manifest.proto",
        "htmlmessages.proto",
        "renderer_rendermessages.proto",
        "stream.proto",
        "google/protobuf/descriptor.proto",
        # SteamUI
        "webuimessages_steamengine.proto",
        "webuimessages_gamerecording.proto",
        "webuimessages_achievements.proto",
        "webuimessages_bluetooth.proto",
        "webuimessages_steaminput.proto",
        "webuimessages_steamos.proto",
        "webuimessages_gamescope.proto",
        "webuimessages_user.proto",
        "webuimessages_leds.proto",
        "webuimessages_sleep.proto",
        "steammessages_appoverview.proto",
        "steammessages_clientsettings.proto",
        "steammessages_clientnotificationtypes.proto",
        "steammessages_childprocessquery.proto",
        "steammessages_gamenetworkingui.proto",
    ]

    def __init__(self, reader: MemoryReader, verbose: bool = False):
        self.reader = reader
        self.verbose = verbose
        self.converter = ProtoConverter()
        self.found_descriptors: Dict[str, bytes] = {}
        self.scanned_regions: Set[int] = set()

    def scan_all_modules(self) -> Dict[str, str]:
        """Сканирует все модули и возвращает {имя_файла: proto_текст}"""
        modules = self.reader.enumerate_modules()
        logger.info(f"Found {len(modules)} modules to scan")

        # Сначала ищем по известным именам
        for name, base, size in modules:
            module_name = os.path.basename(name).lower()
            logger.debug(f"Module: {name} at 0x{base:X} ({size} bytes)")

        # Сканируем каждый модуль
        for name, base, size in modules:
            self._scan_module(name, base, size)

        # Конвертируем найденные дескрипторы
        results = {}
        for desc_name, desc_data in self.found_descriptors.items():
            proto_name, proto_text = self.converter.convert_file_descriptor(desc_data)
            if proto_name and proto_text:
                results[proto_name] = proto_text
                logger.info(f"Converted: {proto_name} ({len(proto_text.splitlines())} lines)")

        return results

    def _scan_module(self, name: str, base: int, size: int):
        """Сканирует один модуль"""
        logger.debug(f"Scanning module: {name} (0x{base:X} - 0x{base + size:X})")

        # Разбиваем на чанки для чтения
        chunk_size = 1024 * 1024  # 1MB chunks
        chunks = []

        for offset in range(0, size, chunk_size):
            read_size = min(chunk_size, size - offset)
            addr = base + offset
            data = self.reader.read_memory(addr, read_size)
            if data:
                chunks.append((addr, data))

        # Сканируем чанки
        for addr, data in chunks:
            self._scan_chunk(data, addr)

    def _scan_chunk(self, data: bytes, base_addr: int):
        """Сканирует чанк памяти на предмет proto дескрипторов"""
        # Поиск по известным именам
        for proto_name in self.STEAM_PROTO_NAMES:
            encoded = proto_name.encode('utf-8')
            offset = 0
            while True:
                idx = data.find(encoded, offset)
                if idx == -1:
                    break

                # Пытаемся найти начало descriptor перед именем
                abs_addr = base_addr + idx
                self._try_extract_descriptor(data, idx, abs_addr, proto_name)
                offset = idx + 1

        # Поиск по паттерну 0x0A (начало FileDescriptorProto)
        for i in range(len(data) - 4):
            if data[i] != 0x0A:
                continue

            try:
                str_len, next_off = read_varint(data, i + 1)
                if str_len < 10 or str_len > 200:
                    continue

                if next_off + str_len > len(data):
                    continue

                name_bytes = data[next_off:next_off + str_len]
                try:
                    name = name_bytes.decode('utf-8')
                except Exception:
                    continue

                if name.endswith('.proto') and len(name) > 10:
                    abs_addr = base_addr + i
                    self._try_extract_descriptor(data, i, abs_addr, name)

            except Exception:
                continue

    def _try_extract_descriptor(self, data: bytes, start: int, abs_addr: int, name: str):
        """Пытается извлечь полный descriptor"""
        if name in self.found_descriptors:
            return

        # Ищем начало descriptor (0x0A перед именем)
        for back in range(max(0, start - 500), start):
            if data[back] != 0x0A:
                continue

            try:
                str_len, next_off = read_varint(data, back + 1)
                if str_len != len(name):
                    continue

                if data[next_off:next_off + str_len] != name.encode('utf-8'):
                    continue

                # Нашли начало. Ищем полный descriptor
                descriptor_start = back

                # Пробуем разные размеры
                for extra in range(200, 100000, 100):
                    end = next_off + str_len + extra
                    if end > len(data):
                        # Нужно прочитать больше памяти
                        remaining = end - len(data)
                        additional = self.reader.read_memory(abs_addr + len(data), remaining)
                        if additional:
                            full_data = data + additional
                        else:
                            break
                    else:
                        full_data = data[:end]

                    candidate = full_data[descriptor_start:]
                    msg = parse_protobuf(candidate)
                    if msg and msg.get_string(FD_NAME) == name:
                        if FD_MESSAGE_TYPE in msg.fields or FD_ENUM_TYPE in msg.fields:
                            self.found_descriptors[name] = candidate
                            logger.info(f"Found descriptor: {name} ({len(candidate)} bytes)")
                            return

            except Exception:
                continue


# ===================== Steam Finder =====================

class SteamFinder:
    """Находит и запускает Steam"""

    def __init__(self):
        self.steam_path: Optional[Path] = None
        self.steam_exe: Optional[Path] = None

    def find_steam(self) -> Optional[Path]:
        """Находит установку Steam"""
        logger.info("Searching for Steam installation...")

        # Windows: через реестр
        if platform.system() == "Windows":
            path = self._find_windows_registry()
            if path:
                return path

        # Поиск по известным путям
        paths = STEAM_PATHS_WINDOWS if platform.system() == "Windows" else STEAM_PATHS_LINUX

        for path_str in paths:
            path = Path(path_str).expanduser()
            if path.exists():
                logger.info(f"Found Steam at: {path}")
                self.steam_path = path
                self.steam_exe = self._find_steam_exe(path)
                return path

        # Через which/find
        path = self._find_steam_which()
        if path:
            return path

        logger.error("Steam not found!")
        return None

    def _find_windows_registry(self) -> Optional[Path]:
        """Windows: поиск через реестр"""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Valve\Steam"
            )
            install_path, _ = winreg.QueryValueEx(key, "InstallPath")
            winreg.CloseKey(key)

            path = Path(install_path)
            if path.exists():
                logger.info(f"Found Steam via registry: {path}")
                self.steam_path = path
                self.steam_exe = path / "steam.exe"
                return path
        except Exception:
            pass

        # Попробовать без WOW6432Node
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Valve\Steam"
            )
            install_path, _ = winreg.QueryValueEx(key, "SteamPath")
            winreg.CloseKey(key)

            path = Path(install_path.replace("/", "\\"))
            if path.exists():
                logger.info(f"Found Steam via registry (HKCU): {path}")
                self.steam_path = path
                self.steam_exe = path / "steam.exe"
                return path
        except Exception:
            pass

        return None

    def _find_steam_which(self) -> Optional[Path]:
        """Поиск через which (Linux/Mac)"""
        try:
            result = subprocess.run(
                ["which", "steam"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                path = Path(result.stdout.strip())
                if path.exists():
                    self.steam_path = path.parent
                    self.steam_exe = path
                    return self.steam_path
        except Exception:
            pass
        return None

    def _find_steam_exe(self, path: Path) -> Optional[Path]:
        """Находит исполняемый файл Steam"""
        if platform.system() == "Windows":
            exe = path / "steam.exe"
        else:
            exe = path / "steam"

        if exe.exists():
            return exe

        # Ищем в подпапках
        for candidate in ["steam.exe", "Steam.exe", "steam"]:
            exe = path / candidate
            if exe.exists():
                return exe

        return None

    def find_steam_processes(self) -> List[Tuple[int, str]]:
        """Находит запущенные процессы Steam"""
        processes = []

        if platform.system() == "Windows":
            processes = self._find_processes_windows()
        elif platform.system() == "Linux":
            processes = self._find_processes_linux()

        return processes

    def _find_processes_windows(self) -> List[Tuple[int, str]]:
        """Windows: поиск процессов через tasklist"""
        try:
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10
            )

            processes = []
            for line in result.stdout.split('\n'):
                if 'steam' in line.lower():
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        name = parts[0].strip('"')
                        pid = int(parts[1].strip('"'))
                        processes.append((pid, name))

            return processes
        except Exception:
            return []

    def _find_processes_linux(self) -> List[Tuple[int, str]]:
        """Linux: поиск через pgrep"""
        try:
            result = subprocess.run(
                ["pgrep", "-a", "steam"],
                capture_output=True,
                text=True,
                timeout=10
            )

            processes = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split(' ', 1)
                    if len(parts) >= 2:
                        pid = int(parts[0])
                        name = parts[1].split('/')[-1].split()[0]
                        processes.append((pid, name))

            return processes
        except Exception:
            return []

    def launch_steam(self) -> bool:
        """Запускает Steam"""
        if not self.steam_exe:
            logger.error("Steam executable not found")
            return False

        logger.info(f"Launching Steam: {self.steam_exe}")

        try:
            if platform.system() == "Windows":
                # Windows: запуск через ShellExecute
                import ctypes
                ctypes.windll.shell32.ShellExecuteW(
                    None, "open", str(self.steam_exe), None, None, 1
                )
            else:
                # Linux: запуск через subprocess
                subprocess.Popen(
                    [str(self.steam_exe)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

            logger.info("Steam launched, waiting for initialization...")
            time.sleep(10)  # Ждём запуска
            return True

        except Exception as e:
            logger.error(f"Failed to launch Steam: {e}")
            return False


# ===================== Main Dumper =====================

class SteamProtoDumper:
    """Главный класс для дампа proto файлов из Steam"""

    def __init__(self, output_dir: str = "./steam_protos_dump", verbose: bool = False):
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        self.finder = SteamFinder()
        self.scanner = None
        self.reader = None
        self.pid = None
        self._running = True

        # Обработка сигналов
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Обработка Ctrl+C"""
        logger.info("\nStopping...")
        self._running = False

    def run(self, no_launch: bool = False, target_pid: int = None, watch: bool = False):
        """Главный цикл"""
        logger.info("=" * 60)
        logger.info(f"RD.py — Steam Protobuf Runtime Dumper v{__version__}")
        logger.info("=" * 60)

        # Создаём папку вывода
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Определяем PID
        if target_pid:
            self.pid = target_pid
            logger.info(f"Using target PID: {self.pid}")
        else:
            self.pid = self._find_or_launch_steam(no_launch)
            if not self.pid:
                return False

        # Дампим proto файлы
        if watch:
            return self._watch_mode()
        else:
            return self._dump_once()

    def _find_or_launch_steam(self, no_launch: bool) -> Optional[int]:
        """Находит или запускает Steam"""
        # Ищем Steam
        steam_path = self.finder.find_steam()
        if steam_path:
            logger.info(f"Steam installation: {steam_path}")

        # Ищем запущенные процессы
        processes = self.finder.find_steam_processes()
        if processes:
            logger.info(f"Found {len(processes)} Steam processes:")
            for pid, name in processes:
                logger.info(f"  PID {pid}: {name}")

            # Выбираем главный процесс
            for pid, name in processes:
                if 'steam.exe' in name.lower() or name == 'steam':
                    logger.info(f"Selected main process: PID {pid}")
                    return pid

            # Если не нашли steam.exe, берём первый
            return processes[0][0]

        # Запускаем Steam если нужно
        if no_launch:
            logger.error("Steam is not running and --no-launch is set")
            return None

        if self.finder.launch_steam():
            # Ждём появления процесса
            for _ in range(30):
                time.sleep(2)
                processes = self.finder.find_steam_processes()
                if processes:
                    for pid, name in processes:
                        if 'steam.exe' in name.lower() or name == 'steam':
                            logger.info(f"Steam started, PID: {pid}")
                            return pid
                    return processes[0][0]

            logger.error("Steam did not start within timeout")
            return None

        return None

    def _dump_once(self) -> bool:
        """Однократный дамп"""
        logger.info(f"Attaching to Steam process (PID: {self.pid})...")

        try:
            self.reader = MemoryReader(self.pid)
        except Exception as e:
            logger.error(f"Cannot attach to process: {e}")
            return False

        logger.info("Scanning memory for protobuf descriptors...")
        self.scanner = ProtoScanner(self.reader, self.verbose)

        results = self.scanner.scan_all_modules()

        if results:
            self._save_results(results)
            self._print_summary(results)
            return True
        else:
            logger.warning("No protobuf descriptors found")
            return False

    def _watch_mode(self) -> bool:
        """Режим мониторинга"""
        logger.info("Watch mode: monitoring for proto changes...")
        logger.info("Press Ctrl+C to stop")

        last_hash = {}

        while self._running:
            try:
                # Переподключаемся если нужно
                if not self.reader:
                    self.reader = MemoryReader(self.pid)

                scanner = ProtoScanner(self.reader, self.verbose)
                results = scanner.scan_all_modules()

                # Проверяем изменения
                current_hash = {}
                for name, text in results.items():
                    h = hashlib.md5(text.encode()).hexdigest()
                    current_hash[name] = h

                    if name not in last_hash or last_hash[name] != h:
                        logger.info(f"Changed: {name}")

                # Сохраняем
                if results:
                    self._save_results(results)

                last_hash = current_hash
                logger.info(f"Scan complete: {len(results)} protos. Next scan in 30s...")

                # Ждём
                for _ in range(30):
                    if not self._running:
                        break
                    time.sleep(1)

            except Exception as e:
                logger.error(f"Error in watch mode: {e}")
                time.sleep(5)
                self.reader = None

        return True

    def _save_results(self, results: Dict[str, str]):
        """Сохраняет результаты"""
        saved = 0
        for name, text in results.items():
            safe_name = name.replace('/', '_').replace('\\', '_')
            filepath = self.output_dir / safe_name

            # Не перезаписываем если не изменилось
            if filepath.exists():
                existing = filepath.read_text(encoding='utf-8')
                if existing == text:
                    continue

            filepath.write_text(text, encoding='utf-8')
            saved += 1

        # Сохраняем манифест
        manifest_path = self.output_dir / "MANIFEST.txt"
        with open(manifest_path, 'w', encoding='utf-8') as f:
            f.write(f"RD.py — Steam Protobuf Runtime Dump\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"PID: {self.pid}\n")
            f.write(f"Files: {len(results)}\n")
            f.write(f"\nFiles:\n")
            for name in sorted(results.keys()):
                f.write(f"  {name}\n")

        logger.info(f"Saved {saved} proto files to {self.output_dir}")

    def _print_summary(self, results: Dict[str, str]):
        """Выводит итоги"""
        logger.info("\n" + "=" * 60)
        logger.info("DUMP COMPLETE")
        logger.info("=" * 60)
        logger.info(f"Output directory: {self.output_dir}")
        logger.info(f"Total proto files: {len(results)}")

        # Статистика по размерам
        total_lines = 0
        for name, text in sorted(results.items()):
            lines = len(text.splitlines())
            total_lines += lines
            logger.info(f"  {name}: {lines} lines")

        logger.info(f"\nTotal lines: {total_lines}")
        logger.info("=" * 60)


# ===================== Hex Dump Utility =====================

class HexDump:
    """Утилита для hex dump памяти (для отладки)"""

    @staticmethod
    def dump(data: bytes, offset: int = 0, length: int = 256) -> str:
        """Форматирует данные в hex dump"""
        lines = []
        end = min(len(data), offset + length)

        for i in range(offset, end, 16):
            chunk = data[i:i + 16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f'  {i:08x}: {hex_str:<48s}  {ascii_str}')

        return '\n'.join(lines)

    @staticmethod
    def find_pattern(data: bytes, pattern: bytes, start: int = 0) -> List[int]:
        """Находит все вхождения паттерна в данных"""
        positions = []
        offset = start
        while True:
            idx = data.find(pattern, offset)
            if idx == -1:
                break
            positions.append(idx)
            offset = idx + 1
        return positions

    @staticmethod
    def extract_string(data: bytes, offset: int, max_len: int = 256) -> str:
        """Извлекает null-terminated строку из данных"""
        end = offset
        while end < len(data) and end < offset + max_len:
            if data[end] == 0:
                break
            end += 1

        try:
            return data[offset:end].decode('utf-8', errors='replace')
        except Exception:
            return ""


# ===================== Descriptor Validator =====================

class DescriptorValidator:
    """Валидация извлечённых protobuf дескрипторов"""

    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def validate_proto_file(self, name: str, text: str) -> bool:
        """Валидирует .proto файл"""
        self.errors.clear()
        self.warnings.clear()

        lines = text.strip().split('\n')
        if not lines:
            self.errors.append("Empty file")
            return False

        # Проверяем syntax declaration
        has_syntax = any('syntax =' in line for line in lines)
        if not has_syntax:
            self.warnings.append("No syntax declaration")

        # Проверяем баланс скобок
        open_braces = text.count('{')
        close_braces = text.count('}')
        if open_braces != close_braces:
            self.errors.append(f"Unbalanced braces: {{ = {open_braces}, }} = {close_braces}")

        # Проверяем что есть хотя бы одно определение
        has_message = any('message ' in line for line in lines)
        has_enum = any('enum ' in line for line in lines)
        has_service = any('service ' in line for line in lines)

        if not (has_message or has_enum or has_service):
            self.warnings.append("No message, enum, or service definitions")

        # Проверяем поля на корректность
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('syntax'):
                continue

            # Проверяем что поля заканчиваются на ;
            if any(stripped.startswith(kw) for kw in ['optional', 'required', 'repeated']):
                if not stripped.endswith(';'):
                    self.errors.append(f"Line {i}: Field doesn't end with ';'")

            # Проверяем что message/enum/service закрываются
            if stripped.startswith(('message', 'enum', 'service')):
                if '{' not in stripped:
                    self.warnings.append(f"Line {i}: Missing opening brace")

        return len(self.errors) == 0

    def get_report(self) -> str:
        """Возвращает отчёт валидации"""
        lines = []
        if self.errors:
            lines.append("ERRORS:")
            for err in self.errors:
                lines.append(f"  - {err}")
        if self.warnings:
            lines.append("WARNINGS:")
            for warn in self.warnings:
                lines.append(f"  - {warn}")
        if not self.errors and not self.warnings:
            lines.append("OK")
        return '\n'.join(lines)


# ===================== Dump Report =====================

@dataclass
class DumpReport:
    """Отчёт о дампе"""
    timestamp: str = ""
    pid: int = 0
    platform: str = ""
    steam_path: str = ""
    modules_scanned: int = 0
    descriptors_found: int = 0
    proto_files_saved: int = 0
    total_lines: int = 0
    total_bytes: int = 0
    errors: List[str] = field(default_factory=list)
    files: Dict[str, int] = field(default_factory=dict)  # name -> lines
    scan_duration: float = 0.0

    def generate(self) -> str:
        """Генерирует текстовый отчёт"""
        lines = [
            "=" * 70,
            "RD.py — STEAM PROTOBUF DUMP REPORT",
            "=" * 70,
            f"Generated:    {self.timestamp}",
            f"Platform:     {self.platform}",
            f"PID:          {self.pid}",
            f"Steam path:   {self.steam_path}",
            f"Scan time:    {self.scan_duration:.1f}s",
            "",
            "STATISTICS:",
            f"  Modules scanned:    {self.modules_scanned}",
            f"  Descriptors found:  {self.descriptors_found}",
            f"  Proto files saved:  {self.proto_files_saved}",
            f"  Total lines:        {self.total_lines}",
            f"  Total bytes:        {self.total_bytes:,}",
            "",
        ]

        if self.files:
            lines.append("FILES:")
            for name in sorted(self.files.keys()):
                lines.append(f"  {name}: {self.files[name]} lines")
            lines.append("")

        if self.errors:
            lines.append("ERRORS:")
            for err in self.errors:
                lines.append(f"  - {err}")
            lines.append("")

        lines.append("=" * 70)
        return '\n'.join(lines)


# ===================== Proto Comparator =====================

class ProtoComparator:
    """Сравнение proto файлов между разными дампами"""

    @staticmethod
    def compare(dir1: str, dir2: str) -> Dict[str, str]:
        """Сравнивает два каталога с proto файлами"""
        changes = {}

        files1 = set(Path(dir1).glob("*.proto"))
        files2 = set(Path(dir2).glob("*.proto"))

        # Новые файлы
        new_files = files2 - files1
        for f in new_files:
            changes[f.name] = "ADDED"

        # Удалённые файлы
        removed_files = files1 - files2
        for f in removed_files:
            changes[f.name] = "REMOVED"

        # Изменённые файлы
        common_files = files1 & files2
        for f in common_files:
            content1 = f.read_text(encoding='utf-8')
            content2 = (Path(dir2) / f.name).read_text(encoding='utf-8')

            if content1 != content2:
                lines1 = len(content1.splitlines())
                lines2 = len(content2.splitlines())
                changes[f.name] = f"MODIFIED ({lines1} -> {lines2} lines)"

        return changes


# ===================== Process Monitor =====================

class ProcessMonitor:
    """Мониторинг процессов Steam"""

    def __init__(self, check_interval: int = 5):
        self.check_interval = check_interval
        self.known_pids: Set[int] = set()
        self._running = False
        self._callback = None

    def on_process_change(self, callback):
        """Регистрирует callback при изменении процессов"""
        self._callback = callback

    def start(self):
        """Запускает мониторинг"""
        self._running = True
        self._monitor_loop()

    def stop(self):
        """Останавливает мониторинг"""
        self._running = False

    def _monitor_loop(self):
        """Основной цикл мониторинга"""
        while self._running:
            current_pids = self._get_steam_pids()

            # Новые процессы
            new_pids = current_pids - self.known_pids
            if new_pids and self._callback:
                for pid in new_pids:
                    self._callback("started", pid)

            # Завершённые процессы
            dead_pids = self.known_pids - current_pids
            if dead_pids and self._callback:
                for pid in dead_pids:
                    self._callback("stopped", pid)

            self.known_pids = current_pids
            time.sleep(self.check_interval)

    def _get_steam_pids(self) -> Set[int]:
        """Получает текущие PID процессов Steam"""
        pids = set()

        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'steam' in line.lower():
                        parts = line.strip().split(',')
                        if len(parts) >= 2:
                            pids.add(int(parts[1].strip('"')))
            else:
                result = subprocess.run(
                    ["pgrep", "-f", "steam"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split('\n'):
                    if line:
                        pids.add(int(line))
        except Exception:
            pass

        return pids


# ===================== Proto Stats =====================

class ProtoStats:
    """Статистика по proto файлам"""

    def __init__(self):
        self.files: Dict[str, Dict[str, Any]] = {}

    def analyze(self, proto_dir: str) -> Dict[str, Any]:
        """Анализирует каталог с proto файлами"""
        proto_path = Path(proto_dir)
        if not proto_path.exists():
            return {}

        stats = {
            "total_files": 0,
            "total_messages": 0,
            "total_enums": 0,
            "total_services": 0,
            "total_fields": 0,
            "total_lines": 0,
            "total_bytes": 0,
            "packages": set(),
            "files": {},
        }

        for proto_file in proto_path.glob("*.proto"):
            content = proto_file.read_text(encoding='utf-8')
            lines = content.splitlines()

            file_stats = {
                "lines": len(lines),
                "bytes": len(content.encode('utf-8')),
                "messages": 0,
                "enums": 0,
                "services": 0,
                "fields": 0,
                "package": "",
            }

            for line in lines:
                stripped = line.strip()
                if stripped.startswith('message '):
                    file_stats["messages"] += 1
                elif stripped.startswith('enum '):
                    file_stats["enums"] += 1
                elif stripped.startswith('service '):
                    file_stats["services"] += 1
                elif any(stripped.startswith(kw) for kw in ['optional', 'required', 'repeated']):
                    file_stats["fields"] += 1
                elif stripped.startswith('package '):
                    pkg = stripped.split('package')[1].split(';')[0].strip()
                    file_stats["package"] = pkg
                    stats["packages"].add(pkg)

            stats["total_files"] += 1
            stats["total_messages"] += file_stats["messages"]
            stats["total_enums"] += file_stats["enums"]
            stats["total_services"] += file_stats["services"]
            stats["total_fields"] += file_stats["fields"]
            stats["total_lines"] += file_stats["lines"]
            stats["total_bytes"] += file_stats["bytes"]
            stats["files"][proto_file.name] = file_stats

        stats["packages"] = list(stats["packages"])
        return stats


# ===================== Enhanced Memory Scanner =====================

class EnhancedProtoScanner(ProtoScanner):
    """Расширенный сканер с дополнительными алгоритмами поиска"""

    def __init__(self, reader: MemoryReader, verbose: bool = False):
        super().__init__(reader, verbose)
        self.signature_hits: Dict[str, int] = defaultdict(int)

    def scan_with_signatures(self) -> Dict[str, str]:
        """Сканирование с использованием сигнатур"""
        modules = self.reader.enumerate_modules()

        for name, base, size in modules:
            # Метод 1: Поиск по известным именам
            self._scan_module(name, base, size)

            # Метод 2: Поиск по сигнатуре FileDescriptorProto
            self._scan_by_signature(name, base, size)

            # Метод 3: Поиск по сигнатуре ".proto\0"
            self._scan_by_extension(name, base, size)

            # Метод 4: Поиск по известным пакетам Steam
            self._scan_by_package(name, base, size)

        # Конвертируем
        results = {}
        for desc_name, desc_data in self.found_descriptors.items():
            proto_name, proto_text = self.converter.convert_file_descriptor(desc_data)
            if proto_name and proto_text:
                results[proto_name] = proto_text

        return results

    def _scan_by_signature(self, module_name: str, base: int, size: int):
        """Метод 2: Поиск по сигнатуре protobuf"""
        chunk_size = 1024 * 1024
        for offset in range(0, size, chunk_size):
            read_size = min(chunk_size, size - offset)
            data = self.reader.read_memory(base + offset, read_size)
            if not data:
                continue

            # FileDescriptorProto signature:
            # Field 1 (name): tag = 0x0A, then varint length, then string
            # Field 6 (message_type): tag = 0x32
            # Field 7 (enum_type): tag = 0x3A
            # Field 8 (service): tag = 0x42

            for i in range(len(data) - 8):
                # Ищем паттерн: 0x0A XX [name] 0x32 или 0x3A
                if data[i] != 0x0A:
                    continue

                try:
                    str_len, next_off = read_varint(data, i + 1)
                    if str_len < 10 or str_len > 200:
                        continue

                    if next_off + str_len + 1 >= len(data):
                        continue

                    name_bytes = data[next_off:next_off + str_len]
                    name = name_bytes.decode('utf-8', errors='replace')

                    if not name.endswith('.proto'):
                        continue

                    # Проверяем что после имени идёт валидное поле
                    after_name = next_off + str_len
                    next_byte = data[after_name]
                    next_field = (next_byte >> 3) & 0x1F
                    next_wire = next_byte & 0x07

                    if next_field in (6, 7, 8) and next_wire == 2:
                        # Потенциальный descriptor
                        self._try_extract_descriptor(data, i, base + offset + i, name)

                except Exception:
                    continue

    def _scan_by_extension(self, module_name: str, base: int, size: int):
        """Метод 3: Поиск по расширению .proto"""
        chunk_size = 1024 * 1024
        for offset in range(0, size, chunk_size):
            read_size = min(chunk_size, size - offset)
            data = self.reader.read_memory(base + offset, read_size)
            if not data:
                continue

            # Ищем .proto\0
            pattern = b'.proto\x00'
            idx = 0
            while True:
                idx = data.find(pattern, idx)
                if idx == -1:
                    break

                # Ищем начало имени
                start = idx
                while start > 0 and data[start - 1] not in (0, 0x0A, 0x00):
                    start -= 1

                name = data[start:idx + 6].decode('utf-8', errors='replace')
                if len(name) > 10 and name.endswith('.proto'):
                    # Ищем descriptor перед именем
                    for back in range(max(0, start - 500), start):
                        if data[back] == 0x0A:
                            self._try_extract_descriptor(data, back, base + offset + back, name)
                            break

                idx += 6

    def _scan_by_package(self, module_name: str, base: int, size: int):
        """Метод 4: Поиск по известным пакетам Steam"""
        steam_packages = [
            b'steammessages_',
            b'webuimessages_',
            b'steamdatagram_',
            b'steamnetworking',
            b'content_manifest',
            b'encrypted_app_ticket',
        ]

        chunk_size = 1024 * 1024
        for offset in range(0, size, chunk_size):
            read_size = min(chunk_size, size - offset)
            data = self.reader.read_memory(base + offset, read_size)
            if not data:
                continue

            for pkg in steam_packages:
                idx = 0
                while True:
                    idx = data.find(pkg, idx)
                    if idx == -1:
                        break

                    # Смотрим что дальше
                    end = idx
                    while end < len(data) and end < idx + 200:
                        if data[end] == 0 or data[end] == 0x0A:
                            break
                        end += 1

                    try:
                        name = data[idx:end].decode('utf-8', errors='replace')
                        if name.endswith('.proto') and len(name) > 10:
                            # Ищем descriptor перед именем
                            for back in range(max(0, idx - 500), idx):
                                if data[back] == 0x0A:
                                    self._try_extract_descriptor(data, back, base + offset + back, name)
                                    break
                    except Exception:
                        pass

                    idx += len(pkg)


# ===================== CLI =====================

def main():
    parser = argparse.ArgumentParser(
        description="RD.py — Steam Protobuf Runtime Dumper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python RD.py                    # Автоматически найдёт и запустит Steam
  python RD.py --output ./protos  # Указать папку вывода
  python RD.py --no-launch        # Не запускать Steam
  python RD.py --pid 1234         # Дампить конкретный PID
  python RD.py --watch            # Режим мониторинга
  python RD.py --stats            # Статистика по уже.dumpленным файлам
  python RD.py --validate         # Валидация proto файлов
  python RD.py --compare d1 d2    # Сравнение двух дампов

Windows: запускать от администратора
Linux:   запускать от root или с CAP_SYS_PTRACE
        """
    )

    parser.add_argument("-o", "--output", default="./steam_protos_dump",
                        help="Директория для вывода (по умолчанию: ./steam_protos_dump)")
    parser.add_argument("--no-launch", action="store_true",
                        help="Не запускать Steam, только дампить если уже запущен")
    parser.add_argument("--pid", type=int, default=None,
                        help="PID процесса для дампа")
    parser.add_argument("--watch", action="store_true",
                        help="Режим мониторинга (обновлять при изменениях)")
    parser.add_argument("--stats", action="store_true",
                        help="Показать статистику по proto файлам")
    parser.add_argument("--validate", action="store_true",
                        help="Валидировать proto файлы")
    parser.add_argument("--compare", nargs=2, metavar=("DIR1", "DIR2"),
                        help="Сравнить два каталога с proto файлами")
    parser.add_argument("--hex-dump", action="store_true",
                        help="Показать hex dump найденных дескрипторов")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Подробный вывод")
    parser.add_argument("--version", action="version",
                        version=f"RD.py {__version__}")

    args = parser.parse_args()

    setup_logging(args.verbose)

    # Режим статистики
    if args.stats:
        stats = ProtoStats()
        result = stats.analyze(args.output)
        if result:
            print(f"\nProto Statistics for: {args.output}")
            print(f"  Total files:      {result['total_files']}")
            print(f"  Total messages:   {result['total_messages']}")
            print(f"  Total enums:      {result['total_enums']}")
            print(f"  Total services:   {result['total_services']}")
            print(f"  Total fields:     {result['total_fields']}")
            print(f"  Total lines:      {result['total_lines']}")
            print(f"  Total bytes:      {result['total_bytes']:,}")
            print(f"  Packages:         {', '.join(result.get('packages', []))}")
        else:
            print("No proto files found")
        return

    # Режим валидации
    if args.validate:
        validator = DescriptorValidator()
        proto_dir = Path(args.output)
        if proto_dir.exists():
            for proto_file in proto_dir.glob("*.proto"):
                content = proto_file.read_text(encoding='utf-8')
                valid = validator.validate_proto_file(proto_file.name, content)
                status = "OK" if valid else "FAIL"
                print(f"  [{status}] {proto_file.name}")
                if not valid:
                    print(f"    {validator.get_report()}")
        return

    # Режим сравнения
    if args.compare:
        dir1, dir2 = args.compare
        changes = ProtoComparator.compare(dir1, dir2)
        if changes:
            print(f"\nComparison: {dir1} vs {dir2}")
            for name, change in sorted(changes.items()):
                print(f"  [{change}] {name}")
        else:
            print("No differences found")
        return

    # Основной режим: дамп
    dumper = SteamProtoDumper(
        output_dir=args.output,
        verbose=args.verbose
    )

    success = dumper.run(
        no_launch=args.no_launch,
        target_pid=args.pid,
        watch=args.watch
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
