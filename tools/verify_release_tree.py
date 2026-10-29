#!/usr/bin/env python3
"""Basic public-release hygiene verifier for the GeDefense TV source tree."""
import os,re,sys
root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
forbidden_names=re.compile(r"(^Next\.md$|SESSION|HANDOFF|AGENT|\.jks$|\.keystore$|^\.env$)")
local_path=re.compile(r"C:\\Users\\|Desktop\\Dev_Bunker|_inbox")
allowed_local={"tools/check_translations.py","tools/build.ps1","tools/test.ps1","tools/verify-source-fidelity.ps1","tools/verify_release_tree.py"}
problems=[]
count=0
for dirpath,dirnames,files in os.walk(root):
    dirnames[:]=[d for d in dirnames if d not in {'.git','build','.gradle','_inbox'}]
    for name in files:
        path=os.path.join(dirpath,name); rel=os.path.relpath(path,root).replace('\\','/')
        count+=1
        if forbidden_names.search(name): problems.append(f"forbidden file: {rel}")
        if os.path.getsize(path)>4_000_000 and rel.startswith('app/src/main/res/'): problems.append(f"oversized asset: {rel}")
        if name.endswith(('.md','.kt','.kts','.xml','.json','.properties','.ps1','.py','.txt')):
            try: text=open(path,encoding='utf-8',errors='replace').read()
            except Exception: continue
            for m in local_path.finditer(text):
                if rel not in allowed_local: problems.append(f"local path in {rel}"); break
            if re.search(r"(?i)ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN (RSA |EC )?PRIVATE KEY-----", text):
                problems.append(f"secret-like content in {rel}")
required=["README.md","README.de.md","README.ru.md","README.fr.md","README.zh-CN.md","README.ja.md","LICENSE","SECURITY.md","ARCHITECTURE.md","THIRD_PARTY_NOTICES.md","app/build.gradle.kts","tv-core/build.gradle.kts","core/build.gradle.kts"]
for r in required:
    if not os.path.isfile(os.path.join(root,r)): problems.append(f"missing required: {r}")
print(f"files scanned: {count}")
if problems:
    print("RESULT: FAIL"); [print(" -",p) for p in problems[:40]]; sys.exit(1)
print("RESULT: PASS (0 findings)")
