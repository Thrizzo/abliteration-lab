r"""
build_gui.py - builds gui/abliteration_gui.html (the standalone walkthrough) from one run folder.
The data collection lives in app/rundata.py (shared with the app server).

    .\.venv\Scripts\python.exe build_gui.py                # latest runs/abliterate_* folder
    .\.venv\Scripts\python.exe build_gui.py runs/abliterate_20261116_181533
"""
import glob, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "app"))
import rundata


def main():
    project = os.getcwd()
    run_dir = sys.argv[1] if len(sys.argv) > 1 else sorted(glob.glob(os.path.join("runs", "abliterate_*")))[-1]
    print("run folder:", run_dir)
    data = rundata.collect(project, run_dir)
    if not (data["measure"] and data["scan"] and data["apply"]):
        raise SystemExit("run folder incomplete - needs sections 4.2-4.6 (layer_analysis, baseline, scan_results, generations)")
    os.makedirs("gui", exist_ok=True)
    with open(os.path.join("gui", "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    tpl = open(os.path.join("gui", "template.html"), encoding="utf-8").read()
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<" + chr(92) + "/")
    out = os.path.join("gui", "abliteration_gui.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(tpl.replace("/*__DATA__*/", blob))
    n = len(data["scan"]["prompts"])
    several = data["choice"].get("layers") or []
    chosen = f"layers {'+'.join(str(x) for x in sorted(several))}" if len(several) > 1 else f"layer {data['choice']['layer']}"
    print(f"built {out} ({os.path.getsize(out) / 1e6:.2f} MB), {chosen}, "
          f"baseline {data['scan']['n_base']}/{n} -> after edit {data['apply']['n_after']}/{n}")


if __name__ == "__main__":
    main()
