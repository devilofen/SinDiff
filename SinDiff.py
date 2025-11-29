# SinDiff.py – The ultimate binary diffing plugin by Sinn
# works on IDA Pro 9.2 forever
# Author: Sinn
# GitHub: https://github.com/devilofen/SinDiff

import idaapi
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_lines
import idautils
import sqlite3
import hashlib
import os

# --------------------------------------------------------------
def export_to_db(db_path):
    if not idaapi.get_input_file_path():
        ida_kernwin.warning("No file loaded! Open a binary first.")
        return False

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS funcs (
        addr INTEGER PRIMARY KEY, name TEXT, asm_hash TEXT, pseudo TEXT)""")

    ida_kernwin.show_wait_box("SinDiff → Exporting functions...")
    count = 0

    for func_ea in idautils.Functions():
        count += 1
        name = idaapi.get_func_name(func_ea) or f"sub_{func_ea:X}"

        asm_lines = []
        func = ida_funcs.get_func(func_ea)
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(head)):
                raw = ida_lines.generate_disasm_line(head, 0)
                if raw:
                    clean = ida_lines.tag_remove(raw).strip()
                    if clean:
                        asm_lines.append(clean)

        asm_hash = hashlib.sha256("\n".join(asm_lines).encode()).hexdigest()

        pseudo = ""
        try:
            cfunc = idaapi.decompile(func_ea)
            if cfunc:
                pseudo = str(cfunc)
        except:
            pass

        cur.execute("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?)",
                    (func_ea, name, asm_hash, pseudo))

        if count % 100 == 0:
            ida_kernwin.replace_wait_box(f"SinDiff → Exported {count} functions...")

    conn.commit()
    conn.close()
    ida_kernwin.hide_wait_box()
    ida_kernwin.info(f"SinDiff → Exported {count} functions → {os.path.basename(db_path)}")
    return True

# --------------------------------------------------------------
def diff_and_show(vuln_db, patched_db):
    try:
        v = sqlite3.connect(vuln_db); vc = v.cursor()
        p = sqlite3.connect(patched_db); pc = p.cursor()

        changes = []
        pc.execute("SELECT addr, name, asm_hash, pseudo FROM funcs")
        for p_addr, p_name, p_asm, p_pseudo in pc.fetchall():
            vc.execute("SELECT asm_hash, pseudo FROM funcs WHERE addr=?", (p_addr,))
            row = vc.fetchone()
            if not row:
                changes.append((p_addr, p_name, "NEW function"))
                continue
            v_asm, v_pseudo = row

            if v_asm == p_asm:
                continue

            note = "Modified"
            if p_pseudo and v_pseudo:
                pl = p_pseudo.lower(); vl = v_pseudo.lower()
                if "memset" in pl and "memset" not in vl:       note += " → memset added"
                if pl.count("if (") > vl.count("if (") + 1:     note += " → extra checks"
                if any(x in vl for x in ["strcpy","sprintf","memcpy"]) and not any(x in pl for x in ["strcpy","sprintf","memcpy"]):
                    note += " → unsafe API removed"

            changes.append((p_addr, p_name, note))

        v.close(); p.close()

        items = [[f"0x{addr:x}", name, reason] for addr, name, reason in changes]

        class SinDiffChooser(ida_kernwin.Choose):
            def __init__(self):
                ida_kernwin.Choose.__init__(self, "SinDiff Results",
                    [["Address", 15 | ida_kernwin.Choose.CHCOL_HEX],
                     ["Name",     30],
                     ["Reason",   70]])
                self.items = items

            def OnGetSize(self):      return len(self.items)
            def OnGetLine(self, n):   return self.items[n]
            def OnSelectLine(self, n):
                addr = int(self.items[n][0], 16)
                ida_kernwin.jumpto(addr)
            def OnClose(self):        pass

        if not changes:
            ida_kernwin.info("SinDiff → No changes found – binaries are identical!")
        else:
            SinDiffChooser().Show()

    except Exception as e:
        ida_kernwin.warning(f"SinDiff error: {e}")

# --------------------------------------------------------------
class SinDiffPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "SinDiff – Binary diffing tool by Sin"
    help = "The fastest way to find patched functions"
    wanted_name = "SinDiff"
    wanted_hotkey = "Alt-Shift-S"   # S for Sinn

    def init(self):  return idaapi.PLUGIN_OK
    def term(self):  pass

    def run(self, arg):
        choice = ida_kernwin.ask_str("export", 0, "SinDiff → Type 'export' or 'diff'")
        if not choice: return
        mode = choice.strip().lower()

        if mode == "export":
            db = ida_kernwin.ask_file(1, "*.db", "SinDiff → Save export as...")
            if db: export_to_db(db)

        elif mode == "diff":
            vdb = ida_kernwin.ask_file(0, "*.db", "SinDiff → Select VULNERABLE export")
            if not vdb: return
            pdb = ida_kernwin.ask_file(0, "*.db", "SinDiff → Select PATCHED export")
            if pdb: diff_and_show(vdb, pdb)
        else:
            ida_kernwin.warning("SinDiff → Type 'export' or 'diff'")

def PLUGIN_ENTRY():
    return SinDiffPlugin()