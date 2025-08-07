# -*- coding: utf-8 -*-
"""
IDA Pro Python 3 Plugin to highlight potential Anti-VM & Anti-Debugging techniques.
Author: Your Name/Nickname & AI Assistant
Version: 2.2 - Fixed false positives in data sections and improved VMXh detection logic.

To install:
1. Copy this file to your IDA's "plugins" directory.
   (e.g., C:\\Program Files\\IDA Pro 9.x\\plugins)
2. Restart IDA Pro.
3. The plugin will be available under "Edit -> Plugins -> Anti-VM/Debug Scanner"
   or via the hotkey Ctrl+Alt-A.
"""

import idc
import idaapi
import idautils
import ida_ua
import ida_bytes
import ida_segment

# --- Plugin Configuration ---
PLUGIN_NAME = "Anti-VM/Debug Scanner"
PLUGIN_COMMENT = "Highlights potential Anti-VM & Anti-Debug artifacts"
PLUGIN_HELP = "This plugin scans the binary for common Anti-VM/Debug techniques and artifacts."
PLUGIN_HOTKEY = "Ctrl-Alt-A"
HIGHLIGHT_COLOR = 0x0000FF  # BGR format for Red

# --- The Plugin Class ---

class AntiVMScannerPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        idaapi.msg(f"[{PLUGIN_NAME}] Plugin initialized. Press {PLUGIN_HOTKEY} to run.\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("="*50 + "\n")
        idaapi.msg(f"[{PLUGIN_NAME}] Starting comprehensive scan...\n")
        idaapi.msg("="*50 + "\n")

        self.clear_highlights()
        
        self.find_mnemonic_based_tricks()
        self.find_special_instruction_patterns()
        self.find_string_artifacts()
        self.find_mac_address_artifacts()
        self.find_api_calls()
        
        idaapi.msg("\n" + "="*50 + "\n")
        idaapi.msg(f"[{PLUGIN_NAME}] Scan finished.\n")
        idaapi.msg("="*50 + "\n")

    def term(self):
        idaapi.msg(f"[{PLUGIN_NAME}] Plugin terminated.\n")

    def _highlight_and_comment(self, ea, comment, color=HIGHLIGHT_COLOR):
        idc.set_color(ea, idc.CIC_ITEM, color)
        current_comment = idc.get_cmt(ea, 1) or ""
        if comment not in current_comment:
            new_comment = f"{comment}; {current_comment}".strip("; ")
            idc.set_cmt(ea, new_comment, 1)
        
        idaapi.msg(f"[+] Found: {comment} at 0x{ea:X}\n")
    
    def clear_highlights(self):
        idaapi.msg("[-] Clearing previous highlights...\n")
        # Итерация только по коду, чтобы не сбрасывать цвета в данных без необходимости
        for ea in self._iterate_code_ea():
            if idc.get_color(ea, idc.CIC_ITEM) == HIGHLIGHT_COLOR:
                idc.set_color(ea, idc.CIC_ITEM, 0xFFFFFF) 

    # НОВАЯ ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ
    def _iterate_code_ea(self):
        """
        Итератор, который проходит только по адресам в исполняемых сегментах.
        Это решает проблему ложных срабатываний в секциях данных.
        """
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg and (seg.perm & ida_segment.SEGPERM_EXEC):
                # idaapi.msg(f"[*] Scanning executable segment: {ida_segment.get_segm_name(seg)}...\n")
                for ea in idautils.Heads(seg.start_ea, seg.end_ea):
                    # Дополнительная проверка, что IDA считает это кодом
                    if idaapi.is_code(idaapi.get_flags(ea)):
                        yield ea

    def find_mnemonic_based_tricks(self):
        idaapi.msg("[-] Searching for suspicious mnemonics in code sections...\n")
        suspicious_mnemonics = {
            "sidt", "sgdt", "sldt", "smsw", "str", "rdtsc", 
            "vmcall", "vmmcall", "icebp", "int 3", "int 2d"
        }
        count = 0
        # ИЗМЕНЕНО: Используем новый итератор по коду
        for ea in self._iterate_code_ea():
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, ea):
                mnem = insn.get_canon_mnem().lower()
                if mnem in suspicious_mnemonics:
                    self._highlight_and_comment(ea, f"Anti-VM/Debug: {mnem.upper()}")
                    count += 1
        idaapi.msg(f"[+] Found {count} suspicious mnemonics.\n")

    def find_special_instruction_patterns(self):
        idaapi.msg("[-] Searching for special instruction patterns in code sections...\n")
        count = 0
        # ИЗМЕНЕНО: Используем новый итератор по коду
        for ea in self._iterate_code_ea():
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, ea):
                continue
                
            mnem = insn.get_canon_mnem().lower()

            if mnem == "cpuid":
                comment = "Anti-VM/Info: CPUID instruction"
                prev_ea = idc.prev_head(ea)
                if prev_ea != idc.BADADDR and idaapi.is_code(idaapi.get_flags(prev_ea)):
                    prev_insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(prev_insn, prev_ea) and prev_insn.get_canon_mnem().lower() == "mov":
                        if idc.print_operand(prev_ea, 0).lower() == "eax":
                            val = idc.get_operand_value(prev_ea, 1)
                            if val == 1:
                                comment = "Anti-VM: CPUID (EAX=1) check for hypervisor bit"
                            elif val == 0x40000000:
                                comment = "Anti-VM: CPUID (EAX=0x40000000) get hypervisor brand"
                self._highlight_and_comment(ea, comment)
                count += 1
            
            # УЛУЧШЕНО: Гибкий поиск VMware VMXh backdoor
            elif mnem == "in" and idc.print_operand(ea, 1).lower() == "dx":
                # Ищем в пределах 10 предыдущих инструкций
                search_ea = ea
                mov_eax_ea = idc.BADADDR
                mov_edx_ea = idc.BADADDR
                
                for _ in range(10): # Ограничиваем глубину поиска
                    search_ea = idc.prev_head(search_ea)
                    if search_ea == idc.BADADDR: break

                    search_insn = ida_ua.insn_t()
                    if not ida_ua.decode_insn(search_insn, search_ea): continue
                    
                    if search_insn.get_canon_mnem().lower() == "mov":
                        op1 = idc.print_operand(search_ea, 0).lower()
                        op2_val = idc.get_operand_value(search_ea, 1)
                        
                        # Ищем `mov edx, 0x5658`
                        if "edx" in op1 and op2_val == 0x5658:
                            mov_edx_ea = search_ea
                        
                        # Ищем `mov eax, 0x564d5868`
                        if "eax" in op1 and op2_val == 0x564d5868:
                            mov_eax_ea = search_ea

                    # Если нашли обе, можно прекратить поиск
                    if mov_eax_ea != idc.BADADDR and mov_edx_ea != idc.BADADDR:
                        break
                
                # Если обе инструкции найдены в окне поиска
                if mov_eax_ea != idc.BADADDR and mov_edx_ea != idc.BADADDR:
                    self._highlight_and_comment(mov_eax_ea, "Anti-VM: VMware backdoor, magic value 'VMXh'")
                    self._highlight_and_comment(mov_edx_ea, "Anti-VM: VMware backdoor, port number")
                    self._highlight_and_comment(ea, "Anti-VM: VMware backdoor, I/O port access")
                    count += 1
                    
            elif mnem == "in" and idc.get_operand_value(ea, 1) == 0x5658: # Старая проверка как fallback
                self._highlight_and_comment(ea, "Anti-VM: VMware backdoor (in eax, 0x5658)")
                count += 1
                
        idaapi.msg(f"[+] Found {count} special instruction patterns.\n")


    def find_string_artifacts(self):
        idaapi.msg("[-] Searching for suspicious string artifacts...\n")
        suspicious_strings = [
            "VBox", "VIRTUAL", "vmware", "qemu", "xen", "KVM", "Oracle",
            "VMWare", "vmmouse", "vmdebug", "VMMEMCTL",
            "HARDWARE\\DEVICEMAP\\Scsi", "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
            "HARDWARE\\Description\\System", "SystemBiosVersion",
            "vboxguest", "vboxsf", "vboxtray", "VBoxMouse",
            "vmtoolsd", "vmhgfs", "vmmemctl.sys",
            "SbieDll",
        ]
        count = 0
        for s in idautils.Strings():
            try:
                str_content = s.string.decode('utf-8', 'ignore').lower()
                for susp_str in suspicious_strings:
                    if susp_str.lower() in str_content:
                        self._highlight_and_comment(s.ea, f"Anti-VM/Sandbox: Suspicious string '{susp_str}'")
                        count += 1
                        break
            except (AttributeError, UnicodeDecodeError):
                continue
        idaapi.msg(f"[+] Found {count} suspicious strings.\n")

    def find_mac_address_artifacts(self):
        idaapi.msg("[-] Searching for suspicious MAC address prefixes in data segments...\n")
        mac_prefixes = {
            b"\x08\x00\x27": "VirtualBox", b"\x00\x05\x69": "VMware",
            b"\x00\x0C\x29": "VMware",     b"\x00\x1C\x42": "Parallels",
            b"\x00\x50\x56": "VMware",
        }
        count = 0
        data_segments = [".rdata", ".data"]
        for seg_name in data_segments:
            seg = idaapi.get_segm_by_name(seg_name)
            if not seg:
                continue

            idaapi.msg(f"[*] Scanning segment '{seg_name}'...\n")
            start_ea = seg.start_ea
            end_ea = seg.end_ea

            for prefix, vm_name in mac_prefixes.items():
                current_ea = start_ea
                while current_ea < end_ea:
                    found_ea = ida_bytes.find_bytes(prefix, current_ea, end_ea, ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)

                    if found_ea != idc.BADADDR:
                        self._highlight_and_comment(found_ea, f"Anti-VM: {vm_name} MAC prefix")
                        count += 1
                        current_ea = found_ea + 1
                    else:
                        break
                        
        idaapi.msg(f"[+] Found {count} potential MAC address artifacts.\n")

    def find_api_calls(self):
        idaapi.msg("[-] Searching for Anti-Debugging API calls...\n")
        anti_debug_apis = {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter"
        }
        count = 0
        for i in range(idaapi.get_import_module_qty()):
            module_name = idaapi.get_import_module_name(i)
            if not module_name: continue

            def enum_imports_cb(ea, name, ord):
                nonlocal count
                if name and name in anti_debug_apis:
                    for ref in idautils.CodeRefsTo(ea, 1):
                        self._highlight_and_comment(ref, f"Anti-Debug: Call to {name}")
                        count += 1
                return True

            idaapi.enum_import_names(i, enum_imports_cb)

        idaapi.msg(f"[+] Found {count} potential Anti-Debugging API calls.\n")

def PLUGIN_ENTRY():
    return AntiVMScannerPlugin()