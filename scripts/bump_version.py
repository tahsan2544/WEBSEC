from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]
vf=root/"VERSION"; pf=root/"pyproject.toml"
old=vf.read_text().strip(); parts=old.split(".")
if len(parts)!=3 or not all(x.isdigit() for x in parts): raise SystemExit(f"Invalid VERSION: {old}")
a,b,c=map(int,parts); new=f"{a}.{b}.{c+1}"
vf.write_text(new+"\n")
s=pf.read_text(); s,n=re.subn(r'version = "[^"]+"',f'version = "{new}"',s,count=1)
if n!=1: raise SystemExit("Could not update pyproject.toml")
pf.write_text(s)
print(f"Version: {old} -> {new}")
