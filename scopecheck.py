"""Find JSX expressions referencing identifiers not declared in their component.

Catches the class of bug where an element is inserted into the wrong function --
the TypeScript build catches it too, but only after a push and a deploy.
"""
import re, sys, glob, os

KEYWORDS = {
    "const","let","var","if","else","return","function","async","await","try","catch","finally",
    "typeof","instanceof","new","delete","void","in","of","for","while","do","switch","case",
    "break","continue","throw","class","extends","super","this","yield","import","export","from",
    "as","default","key","ref","style","className","children",
}

JS_GLOBALS = KEYWORDS | {
    "window","document","console","Math","Number","String","Boolean","Object","Array","JSON",
    "Date","Promise","Set","Map","URL","Error","parseInt","parseFloat","isNaN","setTimeout",
    "clearTimeout","setInterval","clearInterval","localStorage","sessionStorage","fetch",
    "React","undefined","null","true","false","process","performance","requestAnimationFrame",
    "cancelAnimationFrame","encodeURIComponent","decodeURIComponent","Infinity","NaN","Intl",
}

def spans(src):
    starts = [(m.start(), m.group(1)) for m in
              re.finditer(r'^(?:export )?(?:default )?function (\w+)', src, re.M)]
    out = []
    for i, (pos, name) in enumerate(starts):
        end = starts[i+1][0] if i+1 < len(starts) else len(src)
        out.append((name, src[pos:end]))
    return out

def declared_in(body, module_level):
    names = set(module_level)
    # const/let/var bindings, including array and object destructuring
    for m in re.finditer(r'\b(?:const|let|var)\s+([\w{}\[\],:\s.]+?)\s*=', body):
        for n in re.findall(r'\b([A-Za-z_$][\w$]*)\b', m.group(1)):
            names.add(n)
    # function parameters, including destructured props
    for m in re.finditer(r'function\s+\w+\s*\(([\s\S]*?)\)\s*\{', body):
        for n in re.findall(r'\b([A-Za-z_$][\w$]*)\b', m.group(1)):
            names.add(n)
    # arrow params
    for m in re.finditer(r'\(([^()]*)\)\s*=>', body):
        for n in re.findall(r'\b([A-Za-z_$][\w$]*)\b', m.group(1)):
            names.add(n)
    for m in re.finditer(r'\b([A-Za-z_$][\w$]*)\s*=>', body):
        names.add(m.group(1))
    # catch bindings and for-of
    for m in re.finditer(r'\bcatch\s*\(\s*(\w+)', body): names.add(m.group(1))
    for m in re.finditer(r'\bfor\s*\(\s*(?:const|let|var)\s+(\w+)', body): names.add(m.group(1))
    return names

problems = []
for f in sorted(set(glob.glob("src/**/*.tsx", recursive=True))):
    src = open(f).read()
    module_level = set(re.findall(r'^(?:export )?(?:default )?(?:function|const|type|interface)\s+(\w+)', src, re.M))
    for m in re.finditer(r'import\s+(?:(\w+)\s*,\s*)?(?:\{([^}]+)\})?', src):
        if m.group(1): module_level.add(m.group(1))
        for n in (m.group(2) or "").split(","):
            n = n.strip().split(" as ")[-1].strip()
            if n: module_level.add(n)

    for name, body in spans(src):
        ret = body.find("return (")
        if ret == -1: continue
        jsx = body[ret:]
        names = declared_in(body, module_level)
        # identifiers used inside JSX braces: {foo} {foo.bar} {foo?.bar} {foo &&
        used = set()
        for m in re.finditer(r'(?<![.\w$])[{=]\s*\{?\s*([a-z_$][\w$]*)\s*(?:[?.&|)\}\s]|$)', jsx):
            if jsx[max(0, m.start(1) - 1)] != ".":
                used.add(m.group(1))
        for m in re.finditer(r'=\{([a-z_$][\w$]*)\}', jsx):
            used.add(m.group(1))
        missing = sorted(u for u in used
                         if u not in names and u not in JS_GLOBALS and not u.startswith("aria"))
        if missing:
            problems.append(f"  {f}\n      {name}() -> {missing}")

if problems:
    print("OUT-OF-SCOPE REFERENCES:")
    print("\n".join(problems))
    sys.exit(1)
print("scope check: every JSX identifier is declared in its own component")
