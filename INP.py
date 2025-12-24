# ida_export_for_ai.py
# IDAPython script to export decompiled functions, strings, memory, imports and exports for AI analysis

import os
import argparse
import ida_idaapi
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import ida_kernwin
import idautils
import idc

def get_idb_directory():
    """获取 IDB 文件所在目录"""
    idb_path = ida_nalt.get_input_file_path()
    if not idb_path:
        import ida_loader
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    return os.path.dirname(idb_path) if idb_path else os.getcwd()

def ask_custom_export_path(default_path):
    """弹出对话框让用户选择导出目录"""
    if default_path != get_idb_directory():
        path = ida_kernwin.ask_file(default_path, ".ida_exported", "Select export directory")
    else:
        path = default_path
    return path if path else default_path

def ensure_dir(path):
    """确保目录存在"""
    if not os.path.exists(path):
        os.makedirs(path)

def get_callers(func_ea):
    """获取调用当前函数的地址列表"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if idc.is_code(idc.get_full_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))

def get_callees(func_ea):
    """获取当前函数调用的函数地址列表"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))

def format_address_list(addr_list):
    """格式化地址列表为逗号分隔的十六进制字符串"""
    return ", ".join([hex(addr) for addr in addr_list])

def export_decompiled_functions(export_dir):
    """导出所有函数的反编译代码"""
    decompile_dir = os.path.join(export_dir, "decompile")
    ensure_dir(decompile_dir)
    
    total_funcs = 0
    exported_funcs = 0
    failed_funcs = []
    
    for func_ea in idautils.Functions():
        total_funcs += 1
        func_name = idc.get_func_name(func_ea)
        
        try:
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                failed_funcs.append((func_ea, func_name, "decompile returned None"))
                continue
            
            dec_str = str(dec_obj)
            callers = get_callers(func_ea)
            callees = get_callees(func_ea)
            
            output_lines = []
            output_lines.append("/*")
            output_lines.append(" * func-name: {}".format(func_name))
            output_lines.append(" * func-address: {}".format(hex(func_ea)))
            output_lines.append(" * callers: {}".format(format_address_list(callers) if callers else "none"))
            output_lines.append(" * callees: {}".format(format_address_list(callees) if callees else "none"))
            output_lines.append(" */")
            output_lines.append("")
            output_lines.append(dec_str)
            
            output_filename = "{}.c".format(hex(func_ea))
            output_path = os.path.join(decompile_dir, output_filename)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_lines))
            
            exported_funcs += 1
            
            if exported_funcs % 100 == 0:
                print("[+] Exported {} functions...".format(exported_funcs))
                
        except Exception as e:
            failed_funcs.append((func_ea, func_name, str(e)))
            continue
    
    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Failed: {}".format(len(failed_funcs)))
    
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, 'w', encoding='utf-8') as f:
            for addr, name, reason in failed_funcs:
                f.write("{} {} - {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

def export_strings(export_dir):
    """导出所有字符串"""
    strings_path = os.path.join(export_dir, "strings.txt")
    
    string_count = 0
    with open(strings_path, 'w', encoding='utf-8') as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")
        
        for s in idautils.Strings():
            try:
                string_content = str(s)
                str_type = "ASCII"
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                
                f.write("{} | {} | {} | {}\n".format(
                    hex(s.ea),
                    s.length,
                    str_type,
                    string_content.replace('\n', '\\n').replace('\r', '\\r')
                ))
                string_count += 1
            except Exception as e:
                continue
    
    print("[*] Strings Summary:")
    print("    Total strings exported: {}".format(string_count))

def export_imports(export_dir):
    """导出导入表"""
    imports_path = os.path.join(export_dir, "imports.txt")
    
    import_count = 0
    with open(imports_path, 'w', encoding='utf-8') as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            
            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True
            
            ida_nalt.enum_import_names(i, imp_cb)
    
    print("[*] Imports Summary:")
    print("    Total imports exported: {}".format(import_count))

def export_exports(export_dir):
    """导出导出表"""
    exports_path = os.path.join(export_dir, "exports.txt")
    
    export_count = 0
    with open(exports_path, 'w', encoding='utf-8') as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")
        
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)
            
            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1
    
    print("[*] Exports Summary:")
    print("    Total exports exported: {}".format(export_count))

def export_memory(export_dir):
    """导出内存数据，按 1MB 分割，hexdump 格式"""
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)
    
    CHUNK_SIZE = 1 * 1024 * 1024  # 1MB
    BYTES_PER_LINE = 16
    
    total_bytes = 0
    file_count = 0
    
    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue
        
        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)
        
        print("[*] Processing segment: {} ({} - {})".format(
            seg_name, hex(seg_start), hex(seg_end)))
        
        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)
            
            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end)))
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write("# Address        | Hex Bytes                                       | ASCII\n")
                f.write("#" + "-" * 76 + "\n")
                
                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            if byte_val is not None:
                                line_bytes.append(byte_val)
                            else:
                                line_bytes.append(0)
                        else:
                            break
                    
                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue
                    
                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining
                    
                    ascii_part = ""
                    for b in line_bytes:
                        if 0x20 <= b <= 0x7E:
                            ascii_part += chr(b)
                        else:
                            ascii_part += "."
                    
                    f.write("{:016X} | {} | {}\n".format(addr, hex_part.ljust(49), ascii_part))
                    
                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)
            
            file_count += 1
            current_addr = chunk_end
    
    print("\n[*] Memory Export Summary:")
    print("    Total bytes exported: {} ({:.2f} MB)".format(total_bytes, total_bytes / (1024*1024)))
    print("    Files created: {}".format(file_count))

def main(argv=None):
    """主函数"""
    print("=" * 60)
    print("IDA Export for AI Analysis")
    print("=" * 60)

    parser = argparse.ArgumentParser(description='IDA Export for AI Analysis')
    parser.add_argument('-o', '--output', help='Output directory for exported data')
    
    # Handle both standalone script execution and IDA plugin execution
    if argv is None:
        import idc
        argv = idc.ARGV[1:] if len(idc.ARGV) > 1 else []
    
    args, _ = parser.parse_known_args(argv)

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available!")
        print("[!] Strings will still be exported, but no decompilation.")
        has_hexrays = False
    else:
        has_hexrays = True
        print("[+] Hex-Rays decompiler initialized")
    
    idb_dir = get_idb_directory()
    default_export_dir = os.path.join(idb_dir, "export-for-ai")
    
    if args.output:
        export_dir = args.output
    else:
        export_dir = ask_custom_export_path(default_export_dir)
    
    ensure_dir(export_dir)
    
    print("[+] Export directory: {}".format(export_dir))
    print("")
    
    print("[*] Exporting strings...")
    export_strings(export_dir)
    print("")
    
    print("[*] Exporting imports...")
    export_imports(export_dir)
    print("")
    
    print("[*] Exporting exports...")
    export_exports(export_dir)
    print("")
    
    print("[*] Exporting memory...")
    export_memory(export_dir)
    print("")
    
    if has_hexrays:
        print("[*] Exporting decompiled functions...")
        export_decompiled_functions(export_dir)
    
    print("")
    print("=" * 60)
    print("[+] Export completed!")
    print("    Output directory: {}".format(export_dir))
    print("=" * 60)

class AIExportPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "Export IDA data for AI analysis"
    help = "Exports decompiled functions, strings, memory, imports and exports"
    wanted_name = "AI Export"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self):
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        main([])

    def term(self):
        pass

def PLUGIN_ENTRY():
    return AIExportPlugin()

if __name__ == "__main__":
    main()
