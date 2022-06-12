import logging
from typing import Iterable, Tuple, Dict, Any
import struct

from volatility3.framework import interfaces, symbols, exceptions, constants # constants(for peb)
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo, poolscanner

u32 = lambda x : struct.unpack("<I", x)[0]
u16 = lambda x : struct.unpack("<H", x)[0]

vollog = logging.getLogger(__name__)

FILE_DEVICE_DISK = 0x7
FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x14
EXTENSION_CACHE_MAP = {
    "dat": "DataSectionObject",
    "img": "ImageSectionObject",
    "vacb": "SharedCacheMap",
}

class InjectionDetector(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code."""
    _required_framework_version = (1, 0, 0)

    #Define value for vad_info
    VAD_FILENAME = 0
    VAD_BASEADDR = 1
    VAD_SIZE = 2
    VAD_PROTECTION = 3
    VAD_TAG = 4
    VAD_DATA = 5
    VAD_COMMIT_CHARGE = 6
    VAD_IS_DETECTED = 7

    #Define value for peb_info
    PEB_PROC = 0
    PEB_PID = 1
    PEB_IMAGE_FILENAME = 2
    PEB_PPID = 3
    PEB_CREATETIME = 4
    PEB_IMAGE_BASEADDR = 5
    PEB_DLLBASE = 6
    PEB_SIZEOFIMAGE = 7
    PEB_BASEDLLNAME = 8
    PEB_FULLDLLNAME = 9
    PEB_ETHREAD_LIST = 10

    #Tib offset info
    Tib32 = {
    'ExceptionList' : 0x0,
    'StackBase' : 0x4,
    'StackLimit' : 0x8,
    }

    Tib64 = {
    'ExceptionList' : 0x0,
    'StackBase' : 0x8,
    'StackLimit' : 0x10,
    }
    



    @classmethod
    def get_requirements(self):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True),
            requirements.BooleanRequirement(name = 'dump',
                                            description = "Extract injected VADs",
                                            default = False,
                                            optional = True),
            requirements.VersionRequirement(name = 'pslist', component = pslist.PsList, version = (2, 0, 0)),
            requirements.VersionRequirement(name = 'vadinfo', component = vadinfo.VadInfo, version = (2, 0, 0)),
            requirements.ListRequirement(name = 'except',
                             element_type = str,
                             description = "Except Injection Type",
                             optional = True)

        ]

    @classmethod
    def collect_peb_info(self, procs, context: interfaces.context.ContextInterface, 
                         layer_name: str, symbol_table: str):
        self.peb_info = {}
        
        for proc in procs:
            pid = "Unknown"

            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(pid, excp.invalid_address,
                                                                                excp.layer_name))
                if (pid != "Unknown"):
                    self.peb_info[pid].extend(["Unknown", "Unknown", "Unknown", "Unknown", "Unknown", []])
                continue

            self.peb_info[pid] = [proc, 
                                       pid, 
                                       utility.array_to_string(proc.ImageFileName), 
                                       int(proc.InheritedFromUniqueProcessId), # ppid
                                       str(proc.CreateTime)]
            
            # Try to get PEB info
            peb = "Unknown"
            try:
                peb = proc.get_peb()
                proc_image_baseaddr = peb.ImageBaseAddress
            except Exception as excp: # No PEB info
                self.peb_info[pid].extend(["Unknown", "Unknown", "Unknown", "Unknown", "Unknown", []])
                continue

            mod_FullDllName = "Unknown"
            mod_BaseDllName = "Unknown"
            mod_SizeOfImage = "Unknown"
            mod_DllBase = "Unknown"

            # 1st order module is exe
            order_mods = proc.load_order_modules()
            for mod in order_mods:
                try:                 
                    mod_DllBase = mod.DllBase
                    mod_SizeOfImage = mod.SizeOfImage
                    mod_BaseDllName = mod.BaseDllName.get_string()
                    mod_FullDllName = mod.FullDllName.get_string()

                except Exception as excp:
                    pass
                break;

            ethread_list = self.get_ethread_list(proc, context, layer_name, symbol_table)

            self.peb_info[pid].extend([proc_image_baseaddr, mod_DllBase, mod_SizeOfImage, mod_BaseDllName, mod_FullDllName, ethread_list])
    
    @classmethod
    def collect_vad_info(self, context: interfaces.context.ContextInterface,
                         layer_name: str, symbol_table: str):
        peb_info = self.peb_info

        self.vad_info = {}

        for pid in peb_info:

            self.vad_info[pid] = []

            proc = peb_info[pid][self.PEB_PROC]

            isFound = False
            try:        
                for vad in proc.get_vad_root().traverse():
                    vad_protection = vad.get_protection(
                                                vadinfo.VadInfo.protect_values(context, layer_name, symbol_table),
                                                vadinfo.winnt_protections)

                    vad_tag = vad.get_tag()
                    proc_layer_name = proc.add_process_layer()    
                    proc_layer = context.layers[proc_layer_name]

                    vad_size = vad.get_end() - vad.get_start() + 1

                    vad_data = b''
                    if str(vad_tag) == "VadS":
                        vad_data = proc_layer.read(vad.get_start(), 0x100, pad = True)

                        if (vad_data[0] == 0x4D and vad_data[1] == 0x5A): # MZ
                            PE_offset = struct.unpack("<L", vad_data[0x3c:+0x3c+4])[0]
                            
                            if (0x100 < PE_offset + 0x18):
                                vad_data = proc_layer.read(vad.get_start(), PE_offset + 0x18, pad = True)

                            if (vad_data[PE_offset] != 0x50 or vad_data[PE_offset + 1] != 0x45): # PE
                                continue
                                        
                    vad_filename = vad.get_file_name()
                    if isinstance(vad_filename, renderers.NotApplicableValue):
                        vad_filename = "N/A"

                    vad_baseaddr = vad.get_start()

                    self.vad_info[pid].append([str(vad_filename or ''), 
                                                            vad_baseaddr,
                                                            vad_size, 
                                                            str(vad_protection or ''), 
                                                            str(vad_tag or ''),
                                                            vad_data or b'', 
                                                            vad.get_commit_charge(), 
                                                            False])
                    isFound = True

                if not isFound:
                    self.vad_info[pid].append(["NA", 0, 0, "NA", "NA", "NA", 0, False])
            except:
                continue
    
    @classmethod
    def detect_dll_injection(self, peb_info, vad):

        proc = peb_info[self.PEB_PROC]
        vad_protection = vad[self.VAD_PROTECTION]

        if not "WRITE" in vad_protection or not "READ" in vad_protection:
            return False

        vad_data = vad[self.VAD_DATA]
        if not vad_data.isascii():
            return False

        dllpath = vad_data.decode('ascii').replace('\x00', '')
        if (dllpath.find("\\") == -1):
            return False

        order_mods = proc.load_order_modules()
        ret = self.find_module(order_mods, dllpath)

        if ret == True:
            self.detect_info.append([peb_info[self.PEB_PID], "DLL_Injection", peb_info[self.PEB_IMAGE_FILENAME], vad[self.VAD_BASEADDR], vad[self.VAD_SIZE], vad[self.VAD_PROTECTION], dllpath])
        return ret

    @classmethod
    def get_ethread_list(self, proc, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str):
        ethread_list = []
        
        kvo = context.layers[layer_name].config['kernel_virtual_offset']
        
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)
        tleoffset = ntkrnlmp.get_type("_ETHREAD").relative_child_offset("ThreadListEntry")

        current_ethread_flink = proc.ThreadListHead.Flink
        current_ethread = ntkrnlmp.object(object_type="_ETHREAD", offset = current_ethread_flink - tleoffset, absolute = True)
        cid = current_ethread.Cid.UniqueProcess

        ethread_list.append(current_ethread)

        while cid:
            next_ethread = ntkrnlmp.object(object_type="_ETHREAD", offset = current_ethread_flink.Flink - tleoffset, absolute = True)
            current_cid = next_ethread.Cid.UniqueProcess
            thread_entry = next_ethread.Win32StartAddress
            
            if cid != current_cid:
                break

            ethread_list.append(next_ethread)
            current_ethread_flink = current_ethread_flink.Flink

        return ethread_list


    @classmethod
    def detect_main(self, context, layer_name, symbol_table):
        vad_info = self.vad_info
        peb_info = self.peb_info

        self.detect_info = []

        for pid in vad_info:

            for vad in vad_info[pid]:
                vad_tag = vad[self.VAD_TAG]
                vad_protection = vad[self.VAD_PROTECTION]
                
                if vad_tag != "VadS":
                    continue
                
                vad_data = vad[self.VAD_DATA]
                
                if (self.detect_dll_injection(peb_info[pid], vad) == True): # detected
                    continue

    @classmethod
    def find_module(self, modules, findModuleName):
        for mod in modules:
            try:
                if (mod.FullDllName.get_string() == findModuleName):
                    return True
            except Exception as excp:
                pass
            
        return False




    def _generator(self, procs):

        self.collect_peb_info(procs, self.context, self.config["primary"], self.config["nt_symbols"])
        self.collect_vad_info(self.context, self.config["primary"], self.config["nt_symbols"])

        self.detect_main(self.context, self.config["primary"], self.config["nt_symbols"])

        for detect_result in self.detect_info:
            (pid, injection_type, process, vad_base, vad_size, vad_protection, file) = detect_result

            proc = self.peb_info[pid][self.PEB_PROC]
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.layers[proc_layer_name]

            if (proc.get_is_wow64()):
                architecture = "intel"
            else:
                architecture = "intel64"

            data = proc_layer.read(vad_base, 32, pad = True)
            disasm = interfaces.renderers.Disassembly(data, vad_base, architecture)

            yield (0, (pid, injection_type, process, format_hints.Hex(vad_base), format_hints.Hex(vad_size), vad_protection, file, format_hints.HexBytes(data), disasm))


    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Injection_Type", str), ("Process", str), ("Vad_Base", format_hints.Hex), ("Vad_Size", format_hints.Hex), ("Vad_Protection", str), ("File", str), ("Hexdump", format_hints.HexBytes), ("Disasm", interfaces.renderers.Disassembly)
                                   ],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
