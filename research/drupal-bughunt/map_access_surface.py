#!/usr/bin/env python3
import os,re,sys,glob,json
ROOT="/home/user/sources/drupal/modules"
out=[]
# --- D8+ routing.yml: routes with _access:'TRUE' or anonymous _permission ---
ANON_PERMS={"access content","view published content","access site reports"}
for rf in glob.glob(ROOT+"/*/**/*.routing.yml",recursive=True)+glob.glob(ROOT+"/*/*.routing.yml"):
    mod=rf[len(ROOT)+1:].split('/')[0]
    try: txt=open(rf,encoding='utf-8',errors='ignore').read()
    except: continue
    # crude per-route block parse
    blocks=re.split(r'\n(?=\S)',txt)
    for b in blocks:
        rn=re.match(r'([\w.]+):',b)
        if not rn: continue
        route=rn.group(1)
        ctrl=re.search(r'_controller:\s*[\'"]?([^\'"\n]+)',b)
        form=re.search(r'_form:\s*[\'"]?([^\'"\n]+)',b)
        path=re.search(r'path:\s*[\'"]?([^\'"\n]+)',b)
        pub=re.search(r"_access:\s*['\"]?TRUE",b)
        perm=re.search(r"_permission:\s*['\"]([^'\"]+)",b)
        methods=re.search(r'methods:\s*\[([^\]]+)\]',b)
        target=ctrl.group(1) if ctrl else (form.group(1) if form else '')
        is_pub = bool(pub) or (perm and perm.group(1).strip() in ANON_PERMS)
        if is_pub and target:
            m=(methods.group(1) if methods else '').upper()
            write='POST' in m or 'DELETE' in m or 'PUT' in m or 'PATCH' in m
            out.append({"mod":mod,"kind":"route","route":route,"path":path.group(1) if path else '',
                        "target":target,"access":"TRUE" if pub else perm.group(1),
                        "write":write,"file":rf[len(ROOT)+1:]})
# --- D7 hook_menu with 'access callback' => TRUE ---
for mf in glob.glob(ROOT+"/*/*.module")+glob.glob(ROOT+"/*/**/*.module",recursive=True):
    mod=mf[len(ROOT)+1:].split('/')[0]
    try: txt=open(mf,encoding='utf-8',errors='ignore').read()
    except: continue
    for m in re.finditer(r"\$items\[\s*['\"]([^'\"]+)['\"]\s*\]\s*=\s*array\((.*?)\n\s*\);",txt,re.S):
        blk=m.group(2)
        if re.search(r"'access callback'\s*=>\s*TRUE",blk):
            page=re.search(r"'page callback'\s*=>\s*['\"]([^'\"]+)",blk)
            out.append({"mod":mod,"kind":"hook_menu_d7","route":m.group(1),"path":m.group(1),
                        "target":page.group(1) if page else '','access':'TRUE',"write":False,
                        "file":mf[len(ROOT)+1:]})
json.dump(out,open("/home/user/sources/drupal/access_surface.json","w"),indent=0)
print("PUBLIC entry points (pre-auth surface):",len(out))
from collections import Counter
print("by module (top 20):")
for mod,c in Counter(x['mod'] for x in out).most_common(20): print(f"  {c:>3} {mod}")
print("write-capable (POST/DELETE/PUT) public routes:",sum(1 for x in out if x.get('write')))
