
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FrogGlass GUI — EN 🐸 (No pyexiftool; binary-only)
- English UI with emojis
- Uses ExifTool **binary only** when available (no Python wrapper)
- Fallbacks to Pillow/piexif/XMP
- Includes strict "💣 Nuke Metadata (strict)" cleaning and post-clean verify
"""

import sys, os, json, subprocess, webbrowser, mimetypes, hashlib, time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------- Optional deps ----------
try:
    from PIL import Image
except Exception:
    Image = None  # type: ignore
try:
    import piexif
except Exception:
    piexif = None  # type: ignore
try:
    import xmltodict
except Exception:
    xmltodict = None  # type: ignore
try:
    from lxml import etree
except Exception:
    etree = None  # type: ignore
try:
    import folium
except Exception:
    folium = None  # type: ignore
try:
    from geopy.geocoders import Nominatim
    _GEOPY_OK = True
except Exception:
    _GEOPY_OK = False

# ---------- PyQt6 ----------
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFileDialog, QListWidget, QListWidgetItem,
    QLabel, QVBoxLayout, QPushButton, QCheckBox, QSplitter, QTreeWidget,
    QTreeWidgetItem, QLineEdit, QMessageBox, QTabWidget, QToolBar, QStatusBar
)
from PyQt6.QtGui import QPixmap, QAction

# ---------- UI Text ----------
L = {
    "title":               "🐸 FrogGlass — EXIF/XMP/IPTC Reader & Cleaner (No-Wrapper)",
    "tab_preview":         "🖼️ Preview",
    "tab_file":            "📦 File",
    "tab_meta":            "📚 Metadata",
    "tab_map":             "🗺️ Map",
    "btn_add_files":       "➕ Files",
    "btn_add_folder":      "📁 Folder",
    "chk_recurse":         "🔁 Recursive",
    "chk_revgeo":          "🗺️ Reverse Geocode",
    "btn_map":             "🧭 Generate Map",
    "btn_json":            "📝 Export JSON",
    "btn_html":            "📄 HTML Report",
    "btn_clean_copy":      "🧽 Clean EXIF (copy)",
    "btn_clean_inplace":   "⚠️ Clean EXIF (in‑place)",
    "status_added":        "✅ Added {n} file(s).",
    "no_preview":          "🚫 No preview.",
    "err_preview":         "❌ Error loading preview.",
    "reading_meta":        "⏳ Reading metadata…",
    "meta_ready":          "✔️ Metadata ready.",
    "no_gps":              "🧭 No GPS coordinates.",
    "gps_tpl":             "🧭 <b>GPS:</b> {lat}, {lon}{place}<br><a href=\"{osm}\">Open in OpenStreetMap</a>",
    "place_tpl":           "<br>📍 <b>Place:</b> {place}",
    "calc_hash":           "🔍 Computing hashes & file details…",
    "fileinfo_ready":      "📦 File info ready.",
    "pick_one":            "Pick a file in the list.",
    "export_json_ok":      "📝 JSON exported!",
    "report_none":         "No files in the list.",
    "report_ok":           "📄 HTML report generated!",
    "map_no_gps":          "This file has no GPS coordinates.",
    "confirm_overwrite":   "⚠️ This will overwrite the file. Continue?",
    "clean_fail":          "Failed to clean metadata.",
    "clean_ok":            "🧽 Done! Clean file: {path}",
    "search_placeholder":  "🔎 Search metadata (key/value)",
    "images_filter":       "Images (*)",
    "choose_json_dir":     "Choose folder for JSON",
    "choose_report_file":  "Save HTML report",
    "report_filename":     "frog_report.html",
    "html_title":          "FrogGlass Report 🐸✨",
    "html_head":           "<h1>FrogGlass Report 🐸✨</h1>",
}

# ---------- Utils ----------
STATE_FILE = Path.home() / ".frogglass_state.json"
DEFAULT_PREFS = {"inplace_clean_default": False, "verify_after_nuke": True, "open_report_after_save": True}

IMG_EXTS = {
    ".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".gif", ".heic", ".heif",
    ".bmp", ".dng", ".cr2", ".cr3", ".nef", ".arw", ".rw2", ".orf", ".srw", ".raf", ".psd"
}

def which(cmd: str) -> Optional[str]:
    from shutil import which as _which
    return _which(cmd)

def run_exiftool_binary(path: Path) -> Optional[Dict[str, Any]]:
    exe = which("exiftool")
    if not exe:
        return None
    try:
        cmd = [
            exe,
            "-j", "-n", "-G1", "-sort",
            "-a", "-u", "-U", "-struct",
            "-charset", "filename=utf8",
            str(path)
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(proc.stdout)
        if isinstance(data, list) and data:
            return data[0]
    except Exception:
        return None
    return None

def dms_to_deg(dms, ref) -> Optional[float]:
    try:
        deg = dms[0][0] / dms[0][1]
        minute = dms[1][0] / dms[1][1]
        sec = dms[2][0] / dms[2][1]
        sign = -1 if ref in ["S", "W"] else 1
        return sign * (deg + minute / 60 + sec / 3600)
    except Exception:
        return None

def extract_pillow_metadata(path: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if Image is None:
        return out
    try:
        with Image.open(path) as im:
            out["Format"] = im.format
            out["Mode"] = im.mode
            out["Size"] = {"width": im.width, "height": im.height}
            out["Frames"] = getattr(im, "n_frames", 1)
            if hasattr(im, "info") and im.info:
                for k, v in im.info.items():
                    if isinstance(v, (bytes, bytearray)):
                        out[f"info.{k}"] = f"<bytes:{len(v)}>"
                    else:
                        out[f"info.{k}"] = v
            if "dpi" in im.info and isinstance(im.info["dpi"], (tuple, list)):
                out["DPI"] = {"x": im.info["dpi"][0], "y": im.info["dpi"][1] if len(im.info["dpi"])>1 else im.info["dpi"][0]}
            if hasattr(im, "_getexif") and im._getexif():
                exif_raw = im._getexif()
                from PIL.ExifTags import TAGS, GPSTAGS
                exif_named = {}; gps = {}
                for tag_id, val in exif_raw.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    if tag_name == "GPSInfo":
                        for g_tag_id, g_val in val.items():
                            gps[GPSTAGS.get(g_tag_id, str(g_tag_id))] = g_val
                        exif_named["GPSInfo"] = gps
                    else:
                        exif_named[tag_name] = val
                out["EXIF"] = exif_named
            icc = im.info.get("icc_profile")
            if icc:
                out["ICCProfileSize"] = len(icc)
    except Exception as e:
        out["error"] = f"Pillow failed: {e}"
    return out

def extract_piexif(path: Path, container: Dict[str, Any]) -> None:
    if piexif is None:
        return
    try:
        exif_dict = piexif.load(str(path))
        tidy = {}
        for ifd_name, ifd in exif_dict.items():
            if ifd_name == "thumbnail":
                tidy["thumbnail"] = f"<bytes:{len(ifd) if ifd else 0}>"
            else:
                entries = {}
                for k, v in ifd.items():
                    tag_name = piexif.TAGS[ifd_name].get(k, {"name": str(k)})["name"]
                    if isinstance(v, (bytes, bytearray)):
                        entries[tag_name] = f"<bytes:{len(v)}>"
                    else:
                        entries[tag_name] = v
                tidy[ifd_name] = entries
        container["piexif"] = tidy
    except Exception:
        pass

def extract_xmp(path: Path) -> Optional[Dict[str, Any]]:
    raw_xml = None
    try:
        sidecar = path.with_suffix(path.suffix + ".xmp")
        if sidecar.exists():
            raw_xml = sidecar.read_text(encoding="utf-8", errors="ignore")
        else:
            blob = path.read_bytes()
            start = blob.find(b"<x:xmpmeta")
            if start != -1:
                end = blob.find(b"</x:xmpmeta>", start)
                if end != -1:
                    end += len(b"</x:xmpmeta>")
                    raw_xml = blob[start:end].decode("utf-8", errors="ignore")
    except Exception:
        raw_xml = None
    if not raw_xml:
        return None
    if xmltodict:
        try:
            obj = xmltodict.parse(raw_xml, process_namespaces=False)
            return {"_raw": f"<xml:{len(raw_xml)}>", "xmp": obj}
        except Exception:
            pass
    if etree:
        try:
            tree = etree.fromstring(raw_xml.encode("utf-8", errors="ignore"))
            pretty = etree.tostring(tree, pretty_print=True, encoding=str)
            return {"_raw": f"<xml:{len(raw_xml)}>", "xmp_pretty": pretty}
        except Exception:
            pass
    return {"_raw": raw_xml}

def try_get_gps(tags: Dict[str, Any]) -> Optional[Tuple[float, float]]:
    lat = None; lon = None
    for k in ("GPSLatitude", "Composite:GPSLatitude", "EXIF:GPSLatitude"):
        if k in tags:
            lat = tags[k]; break
    for k in ("GPSLongitude", "Composite:GPSLongitude", "EXIF:GPSLongitude"):
        if k in tags:
            lon = tags[k]; break
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        return float(lat), float(lon)
    exif = tags.get("EXIF")
    if isinstance(exif, dict):
        gp = exif.get("GPSInfo")
        if isinstance(gp, dict):
            lat = dms_to_deg(gp.get("GPSLatitude"), gp.get("GPSLatitudeRef", "N"))
            lon = dms_to_deg(gp.get("GPSLongitude"), gp.get("GPSLongitudeRef", "E"))
            if isinstance(lat, float) and isinstance(lon, float):
                return lat, lon
    return None

def reverse_geocode_nominatim(lat: float, lon: float) -> Optional[Dict[str, Any]]:
    if not _GEOPY_OK:
        return None
    try:
        geolocator = Nominatim(user_agent="FrogGlassGUI-EN/nowrapper/1.0")
        loc = geolocator.reverse((lat, lon), language="en")
        if loc:
            return {"address": loc.address, "raw": loc.raw}
    except Exception:
        return None
    return None

def generate_map(lat: float, lon: float, title: str, where: Optional[str], html_dir: Path) -> Optional[Path]:
    html_dir.mkdir(parents=True, exist_ok=True)
    if folium is None:
        outpath = html_dir / f"{title}.map.html"
        link = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"
        body = f"""<!DOCTYPE html><html><body>
<h3>🧭 Map — {title}</h3>
<p>Install folium: <code>pip install folium</code></p>
<p>OpenStreetMap: <a href="{link}">{link}</a></p>
</body></html>"""
        outpath.write_text(body, encoding="utf-8"); return outpath
    m = folium.Map(location=[lat, lon], zoom_start=15)
    popup = where if where else f"{lat:.6f}, {lon:.6f}"
    import folium as _f
    _f.Marker([lat, lon], popup=popup).add_to(m)
    outpath = html_dir / f"{title}.map.html"
    m.save(str(outpath)); return outpath

def file_insights(path: Path, pil_info: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    st = path.stat()
    mime = mimetypes.guess_type(str(path))[0]
    info = {
        "Name": path.name,
        "Path": str(path),
        "SizeBytes": st.st_size,
        "Modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
        "Created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_ctime)),
        "MIME": mime or "unknown",
    }
    try:
        def hsum(algo):
            h = hashlib.new(algo)
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1<<20), b""):
                    h.update(chunk)
            return h.hexdigest()
        info["MD5"] = hsum("md5")
        info["SHA1"] = hsum("sha1")
        info["SHA256"] = hsum("sha256")
    except Exception:
        pass
    if pil_info:
        info["Format"] = pil_info.get("Format")
        info["Mode"] = pil_info.get("Mode")
        info["Frames"] = pil_info.get("Frames")
        sz = pil_info.get("Size")
        if isinstance(sz, dict):
            info["Width"] = sz.get("width")
            info["Height"] = sz.get("height")
        dpi = pil_info.get("DPI")
        if isinstance(dpi, dict):
            info["DPIx"] = dpi.get("x")
            info["DPIy"] = dpi.get("y", dpi.get("x"))
        icc = pil_info.get("ICCProfileSize")
        if icc:
            info["ICCProfileBytes"] = icc
        ex = pil_info.get("EXIF")
        if isinstance(ex, dict):
            ori = ex.get("Orientation") or ex.get("Image Orientation")
            if ori:
                info["EXIF.Orientation"] = ori
    return info

def read_all_metadata(path: Path) -> Dict[str, Any]:
    tags: Dict[str, Any] = {}
    etb = run_exiftool_binary(path)
    if etb:
        tags.update(etb)
    pillow_meta = extract_pillow_metadata(path)
    for k, v in (pillow_meta or {}).items():
        if k in tags and isinstance(tags[k], dict) and isinstance(v, dict):
            tags[k].update(v)
        else:
            tags.setdefault(k, v)
    extract_piexif(path, tags)
    xmp = extract_xmp(path)
    if xmp:
        tags["XMP"] = xmp
    return tags

# ---- Cleaning (standard) ----
def clean_exif(path: Path, in_place: bool=False) -> Optional[Path]:
    exe = which("exiftool")
    if exe:
        try:
            if in_place:
                subprocess.run([exe, "-all=", "-overwrite_original", str(path)], check=True)
                return path
            else:
                out = path.parent / (path.stem + "_clean" + path.suffix)
                subprocess.run([exe, "-all=", "-o", str(out), str(path)], check=True)
                return out
        except Exception:
            pass
    if Image is None:
        return None
    try:
        with Image.open(path) as im:
            fmt = (im.format or "").upper()
            if fmt in {"JPEG", "JPG"} and piexif is not None:
                dst = (path if in_place else path.parent / (path.stem + "_clean" + path.suffix))
                if in_place:
                    tmp = path.parent / (path.stem + "_tmpclean" + path.suffix)
                    im.save(tmp, "JPEG", exif=b"", quality=95, optimize=True)
                    os.replace(tmp, path); return path
                else:
                    im.save(dst, "JPEG", exif=b"", quality=95, optimize=True)
                    return dst
            dst = (path if in_place else path.parent / (path.stem + "_clean" + path.suffix))
            im2 = im
            if im.mode in ("P", "PA"):
                im2 = im.convert("RGBA")
            im2.save(dst, format=im.format)
            return dst
    except Exception:
        return None

# ---- Strict cleaning helpers ----
NUKE_ARGS = [
    "-all=",
    "-unsafe",
    "-icc_profile:all=",
    "-jfif:all=",
    "-jfxx:all=",
    "-iptc:all=",
    "-xmp:all=",
    "-photoshop:all=",
    "-thumbnailimage=",
    "-preview:all=",
    "-comment=",
    "-composite:all=",
    "-makernotes:all=",
    "-exif:all=",
    "-ifd0:all=",
    "-ifd1:all=",
    "-ifd2:all=",
    "-adobe:all=",
]

def _pillow_strip_write(src_path: Path, dst_path: Path) -> bool:
    if Image is None:
        return False
    try:
        with Image.open(src_path) as im:
            fmt = (im.format or "").upper()
            kw = {}
            if fmt in {"JPEG", "JPG"}:
                kw = {"exif": b""}
            if fmt in {"WEBP"}:
                kw.update({"exif": None, "icc_profile": None, "xmp": None})
            if im.mode in ("P", "PA"):
                im = im.convert("RGBA")
            im.save(dst_path, format=im.format, **kw)
        return True
    except Exception:
        return False

def clean_exif_strict(path: Path, in_place: bool=False) -> Optional[Path]:
    exe = which("exiftool")
    if exe:
        try:
            if in_place:
                subprocess.run([exe, "-overwrite_original", *NUKE_ARGS, str(path)], check=True)
                return path
            else:
                out = path.parent / (path.stem + "_clean" + path.suffix)
                subprocess.run([exe, *NUKE_ARGS, "-o", str(out), str(path)], check=True)
                return out
        except Exception:
            pass
    dst = path if in_place else path.parent / (path.stem + "_clean" + path.suffix)
    ok = _pillow_strip_write(path, dst)
    return dst if ok else None

def verify_no_metadata(path: Path) -> Tuple[bool, Dict[str, Any]]:
    """Return (ok, remaining_tags) using exiftool binary when available.
       ok=True if nothing remains besides File/System groups.
    """
    exe = which("exiftool")
    if not exe:
        return (True, {})  # can't verify without exiftool; assume ok
    try:
        proc = subprocess.run([exe, "-j", "-n", "-G1", "-a", "-u", "-U", str(path)],
                              capture_output=True, text=True, check=True)
        data = json.loads(proc.stdout)
        if not isinstance(data, list) or not data:
            return (True, {})
        d = data[0]
        rem = {}
        for k, v in d.items():
            ks = str(k)
            if ks.lower().startswith("file") or ks.lower().startswith("system") or ks == "SourceFile":
                continue
            if ":" in ks and ks.split(":", 1)[0].lower() in ("file", "system"):
                continue
            rem[ks] = v
        return (len(rem) == 0, rem)
    except Exception:
        return (True, {})

# ---------- GUI ----------
class FrogGlassGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(L["title"])
        self.resize(1280, 780)

        # File list
        self.listWidget = QListWidget()
        self.listWidget.setSelectionMode(self.listWidget.SelectionMode.ExtendedSelection)
        self.setAcceptDrops(True)
        self.listWidget.itemSelectionChanged.connect(self.on_select_item)

        # Tabs
        self.tabs = QTabWidget()

        # Preview
        self.previewLabel = QLabel(L["tab_preview"])
        self.previewLabel.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.previewLabel.setMinimumSize(QSize(340, 240))
        self.previewLabel.setStyleSheet("QLabel{background:#111;color:#aaa;border:1px solid #333;}")
        w_preview = QWidget(); v1 = QVBoxLayout(w_preview); v1.addWidget(self.previewLabel)
        self.tabs.addTab(w_preview, L["tab_preview"])

        # File info
        self.fileTree = QTreeWidget(); self.fileTree.setHeaderLabels(["Field", "Value"])
        w_file = QWidget(); vfile = QVBoxLayout(w_file); vfile.addWidget(self.fileTree)
        self.tabs.addTab(w_file, L["tab_file"])

        # Metadata
        self.searchBox = QLineEdit(); self.searchBox.setPlaceholderText(L["search_placeholder"])
        self.searchBox.textChanged.connect(self.filter_tree)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Key", "Value"])
        w_meta = QWidget(); v2 = QVBoxLayout(w_meta); v2.addWidget(self.searchBox); v2.addWidget(self.tree)
        self.tabs.addTab(w_meta, L["tab_meta"])

        # Map
        self.mapInfo = QLabel(L["no_gps"]); self.mapInfo.setWordWrap(True)
        w_map = QWidget(); v3 = QVBoxLayout(w_map); v3.addWidget(self.mapInfo)
        self.tabs.addTab(w_map, L["tab_map"])

        # Splitter
        sp = QSplitter(); sp.addWidget(self.listWidget); sp.addWidget(self.tabs); sp.setStretchFactor(1,1)
        self.setCentralWidget(sp)

        # Toolbar
        tb = QToolBar("Tools"); self.addToolBar(tb)
        act_add_files = QAction(L["btn_add_files"], self); act_add_files.triggered.connect(self.add_files); tb.addAction(act_add_files)
        act_add_folder = QAction(L["btn_add_folder"], self); act_add_folder.triggered.connect(self.add_folder); tb.addAction(act_add_folder)
        self.chk_recurse = QCheckBox(L["chk_recurse"]); tb.addWidget(self.chk_recurse)
        tb.addSeparator()
        self.chk_revgeo = QCheckBox(L["chk_revgeo"]); tb.addWidget(self.chk_revgeo)
        btn_map = QPushButton(L["btn_map"]); btn_map.clicked.connect(self.generate_selected_map); tb.addWidget(btn_map)
        tb.addSeparator()
        btn_export_json = QPushButton(L["btn_json"]); btn_export_json.clicked.connect(self.export_selected_json); tb.addWidget(btn_export_json)
        btn_export_json_sel = QPushButton("📝 Export JSON (Selected)"); btn_export_json_sel.clicked.connect(self.export_json_batch_selected); tb.addWidget(btn_export_json_sel)
        btn_export_html = QPushButton(L["btn_html"]); btn_export_html.clicked.connect(self.export_html_report); tb.addWidget(btn_export_html)
        btn_export_html_sel = QPushButton("📄 HTML Report (Selected)"); btn_export_html_sel.clicked.connect(self.export_html_report_selected); tb.addWidget(btn_export_html_sel)
        tb.addSeparator()
        act_prefs = QAction("⚙️ Preferences", self); act_prefs.triggered.connect(self.open_prefs); tb.addAction(act_prefs)
        tb.addSeparator()
        btn_clean_copy = QPushButton(L["btn_clean_copy"]); btn_clean_copy.clicked.connect(lambda: self.clean_selected(False)); tb.addWidget(btn_clean_copy)
        btn_clean_inplace = QPushButton(L["btn_clean_inplace"]); btn_clean_inplace.clicked.connect(lambda: self.clean_selected(True)); tb.addWidget(btn_clean_inplace)
        # Strict nuke
        btn_nuke = QPushButton("💣 Nuke Metadata (strict)"); btn_nuke.clicked.connect(self.nuke_selected); tb.addWidget(btn_nuke)
        tb.addSeparator()
        btn_remove = QPushButton("🗑️ Remove Selected"); btn_remove.clicked.connect(self.remove_selected); tb.addWidget(btn_remove)
        btn_clear = QPushButton("🧹 Clear List"); btn_clear.clicked.connect(self.clear_list); tb.addWidget(btn_clear)
        tb.addSeparator()
        btn_refresh_sel = QPushButton("🔄 Refresh Selected"); btn_refresh_sel.clicked.connect(self.refresh_selected); tb.addWidget(btn_refresh_sel)
        btn_refresh_all = QPushButton("🔁 Refresh All"); btn_refresh_all.clicked.connect(self.refresh_all); tb.addWidget(btn_refresh_all)
        tb.addSeparator()
        btn_delete = QPushButton("☠️ Delete from Disk"); btn_delete.setToolTip("Permanently delete selected file(s) from disk"); btn_delete.clicked.connect(self.delete_selected); tb.addWidget(btn_delete)

        self.status = QStatusBar(); self.setStatusBar(self.status)
        from PyQt6.QtWidgets import QProgressBar as _QPB
        self._progress = _QPB(); self._progress.setMaximumWidth(220); self._progress.setVisible(False)
        self.status.addPermanentWidget(self._progress)

        # Data
        self.files: List[Path] = []
        self.meta_cache: Dict[str, Dict[str, Any]] = {}
        self.revgeo_cache: Dict[str, Dict[str, Any]] = {}
        self.fileinfo_cache: Dict[str, Dict[str, Any]] = {}
        self.prefs: Dict[str, Any] = DEFAULT_PREFS.copy()

        # Load persisted list
        try:
            if STATE_FILE.exists():
                import json as _json
                data = _json.loads(STATE_FILE.read_text(encoding="utf-8"))
                saved = data.get("files", [])
                self._add_paths([Path(s) for s in saved if Path(s).exists()])
                prefs = data.get("prefs", {})
                if isinstance(prefs, dict):
                    self.prefs.update(prefs)
        except Exception:
            pass

    # --- Files ---
    def add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Choose images", "", L["images_filter"])
        if not paths: return
        self._add_paths([Path(p) for p in paths])

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Choose folder")
        if not folder: return
        p = Path(folder); recurse = self.chk_recurse.isChecked()
        to_add = []
        if recurse:
            for f in p.rglob("*"):
                if f.suffix.lower() in IMG_EXTS: to_add.append(f)
        else:
            for f in p.glob("*"):
                if f.suffix.lower() in IMG_EXTS and f.is_file(): to_add.append(f)
        self._add_paths(to_add)

    def _add_paths(self, paths: List[Path]):
        added = 0
        for f in paths:
            if f.exists() and f.suffix.lower() in IMG_EXTS:
                self.files.append(f)
                self.listWidget.addItem(QListWidgetItem(str(f)))
                added += 1
        self.status.showMessage(L["status_added"].format(n=added), 4000)

    # --- Selection ---
    def on_select_item(self):
        items = self.listWidget.selectedItems()
        if not items: return
        path = Path(items[0].text())
        self.show_preview(path)
        self.show_metadata(path)
        self.show_fileinfo(path)

    def show_preview(self, path: Path):
        try:
            pix = QPixmap(str(path))
            if pix.isNull():
                self.previewLabel.setText(L["no_preview"])
            else:
                scaled = pix.scaled(self.previewLabel.size()*1.0, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
                self.previewLabel.setPixmap(scaled)
        except Exception:
            self.previewLabel.setText(L["err_preview"])

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.on_select_item()

    # --- Metadata ---
    def show_metadata(self, path: Path):
        key = str(path)
        if key not in self.meta_cache:
            self.status.showMessage(L["reading_meta"])
            tags = read_all_metadata(path)
            self.meta_cache[key] = tags
        else:
            tags = self.meta_cache[key]

        self.tree.clear()
        def add_node(parent, d: Dict[str, Any]):
            for k, v in sorted(d.items(), key=lambda kv: kv[0]):
                item = QTreeWidgetItem(parent, [str(k), self._val_str(v)])
                if isinstance(v, dict):
                    add_node(item, v)
        add_node(self.tree.invisibleRootItem(), tags)
        self.tree.expandToDepth(1)

        gps = try_get_gps(tags)
        if gps:
            lat, lon = gps
            place = ""
            if self.chk_revgeo.isChecked():
                cache_key = f"{lat:.6f},{lon:.6f}"
                if cache_key not in self.revgeo_cache:
                    self.revgeo_cache[cache_key] = reverse_geocode_nominatim(lat, lon) or {}
                addr = self.revgeo_cache[cache_key].get("address")
                if addr:
                    place = L["place_tpl"].format(place=addr)
            osm = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"
            html = L["gps_tpl"].format(lat=f"{lat:.6f}", lon=f"{lon:.6f}", place=place, osm=osm)
            self.mapInfo.setText(html)
        else:
            self.mapInfo.setText(L["no_gps"])

        self.status.showMessage(L["meta_ready"], 2000)

    def _val_str(self, v: Any) -> str:
        if isinstance(v, (dict, list)):
            try:
                return json.dumps(v, ensure_ascii=False)[:10000]
            except Exception:
                return str(v)[:10000]
        return str(v)

    def filter_tree(self, text: str):
        text = text.strip().lower()
        def match(item: QTreeWidgetItem) -> bool:
            key = item.text(0).lower(); val = item.text(1).lower()
            return (text in key) or (text in val)
        def recurse(item: QTreeWidgetItem) -> bool:
            visible = match(item)
            for i in range(item.childCount()):
                child = item.child(i)
                if recurse(child): visible = True
            item.setHidden(not visible); return visible
        root = self.tree.invisibleRootItem()
        for i in range(root.childCount()): recurse(root.child(i))

    # --- File/Insights ---
    def show_fileinfo(self, path: Path):
        key = str(path)
        pil_info = None
        if key in self.meta_cache:
            pil_info = {k: self.meta_cache[key].get(k) for k in ("Format","Mode","Size","Frames","DPI","ICCProfileSize","EXIF")}
        if key not in self.fileinfo_cache:
            self.status.showMessage(L["calc_hash"])
            self.fileinfo_cache[key] = file_insights(path, pil_info)
        info = self.fileinfo_cache[key]
        self.fileTree.clear()
        for k in sorted(info.keys()):
            self.fileTree.addTopLevelItem(QTreeWidgetItem([str(k), str(info[k])]))
        self.fileTree.expandAll()
        self.status.showMessage(L["fileinfo_ready"], 2000)

    # --- Exports ---
    def export_selected_json(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "JSON", L["pick_one"]); return
        outdir = QFileDialog.getExistingDirectory(self, L["choose_json_dir"])
        if not outdir: return
        path = Path(items[0].text())
        tags = self.meta_cache.get(str(path)) or read_all_metadata(path)
        (Path(outdir) / (path.stem + ".frogglass.json")).write_text(
            json.dumps(tags, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        QMessageBox.information(self, "JSON", L["export_json_ok"])

    def export_html_report(self):
        if self.listWidget.count() == 0:
            QMessageBox.information(self, "Report", L["report_none"]); return
        save, _ = QFileDialog.getSaveFileName(self, "Save HTML report", L["report_filename"], "HTML (*.html)")
        if not save: return
        rows = []
        for i in range(self.listWidget.count()):
            path = Path(self.listWidget.item(i).text())
            tags = self.meta_cache.get(str(path)) or read_all_metadata(path)
            gps = try_get_gps(tags)
            gps_str = f"{gps[0]:.6f}, {gps[1]:.6f}" if gps else ""
            rows.append(f"""
<section>
  <h2>{path.name}</h2>
  <p><b>Path:</b> {path}</p>
  <p><b>GPS:</b> {gps_str}</p>
  <details><summary>Tags</summary>
  <pre>{json.dumps(tags, ensure_ascii=False, indent=2)[:300000]}</pre>
  </details>
</section>
<hr/>""")
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>{L["html_title"]}</title>
<style>body{{font-family:system-ui;margin:24px}} pre{{white-space:pre-wrap;background:#111;color:#0f0;padding:12px;border-radius:10px}}</style>
</head><body>
{L["html_head"]}
{''.join(rows)}
</body></html>"""
        Path(save).write_text(html, encoding="utf-8")
        QMessageBox.information(self, "Report", L["report_ok"])

    # --- Map ---
    def generate_selected_map(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "Map", L["pick_one"]); return
        path = Path(items[0].text())
        tags = self.meta_cache.get(str(path)) or read_all_metadata(path)
        gps = try_get_gps(tags)
        if not gps:
            QMessageBox.warning(self, "Map", L["map_no_gps"]); return
        lat, lon = gps
        where = None
        if self.chk_revgeo.isChecked():
            rg = reverse_geocode_nominatim(lat, lon)
            where = rg.get("address") if rg else None
        out = generate_map(lat, lon, path.stem, where, Path("maps"))
        if out:
            webbrowser.open(str(Path(out).resolve()))

    # --- Cleaning (standard button) ---
    def clean_selected(self, in_place: bool):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "Clean EXIF", L["pick_one"]); return
        if in_place:
            ans = QMessageBox.question(self, "Confirm", L["confirm_overwrite"])
            if ans != QMessageBox.StandardButton.Yes: return
        successes = 0; fails = 0
        new_files = []
        for it in items:
            path = Path(it.text())
            out = clean_exif(path, in_place=in_place)
            if out:
                successes += 1
                self.meta_cache.pop(str(out), None)
                if not in_place and out != path:
                    new_files.append(out)
            else:
                fails += 1
        if new_files:
            self._add_paths(new_files)
        QMessageBox.information(self, "Clean EXIF", f"✅ {successes} cleaned, ❌ {fails} failed.")

    # --- Strict Nuke button ---
    def nuke_selected(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "Nuke Metadata", L["pick_one"]); return
        ans = QMessageBox.question(self, "Confirm", "This will remove ALL metadata on ALL selected files. Continue?")
        if ans != QMessageBox.StandardButton.Yes: return
        successes = 0; fails = 0; remains = []
        for it in items:
            path = Path(it.text())
            out = clean_exif_strict(path, in_place=True)
            if not out:
                fails += 1; continue
            ok, rem = verify_no_metadata(out)
            if ok:
                successes += 1
            else:
                remains.append((path.name, list(rem.keys())[:12]))
            self.meta_cache.pop(str(out), None)
        msg = f"✅ {successes} nuked"
        if fails:
            msg += f", ❌ {fails} failed"
        if remains:
            tail = "; ".join([f"{n}: {', '.join(keys)}" for n, keys in remains[:5]])
            msg += f"; ⚠️ remaining tags -> {tail}"
        QMessageBox.information(self, "Nuke Metadata", msg)


    # --- List Management ---
    def remove_selected(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "Remove", L["pick_one"]); return
        item = items[0]
        path_str = item.text()
        # remove from list widget
        row = self.listWidget.row(item)
        self.listWidget.takeItem(row)
        # remove from internal lists/caches
        try:
            self.files = [p for p in self.files if str(p) != path_str]
        except Exception:
            pass
        self.meta_cache.pop(path_str, None)
        self.fileinfo_cache.pop(path_str, None)
        # update right pane
        self.previewLabel.setText(L["no_preview"])
        self.fileTree.clear()
        self.tree.clear()
        self.mapInfo.setText(L["no_gps"])
        self.status.showMessage("🗑️ Removed.", 2000)

    def clear_list(self):
        self.listWidget.clear()
        self.files = []
        self.meta_cache.clear()
        self.fileinfo_cache.clear()
        self.revgeo_cache.clear()
        self.previewLabel.setText(L["no_preview"])
        self.fileTree.clear()
        self.tree.clear()
        self.mapInfo.setText(L["no_gps"])
        self.status.showMessage("🧹 List cleared.", 2000)

    def refresh_selected(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "Refresh", L["pick_one"]); return
        for it in items:
            path = it.text()
            self.meta_cache.pop(path, None)
            self.fileinfo_cache.pop(path, None)
        self.on_select_item()
        self.status.showMessage(f"🔄 Refreshed {len(items)} item(s).", 2000)

    def refresh_all(self):
        # clear caches but keep list
        self.meta_cache.clear()
        self.fileinfo_cache.clear()
        # if something is selected, re-render it
        self.on_select_item()
        self.status.showMessage("🔁 All items refreshed.", 2000)



    def delete_selected(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "Delete", L["pick_one"]); return
        count = len(items)
        ans = QMessageBox.question(self, "Confirm delete",
                                   f"THIS WILL PERMANENTLY DELETE {count} FILE(S) FROM DISK. Are you absolutely sure?")
        if ans != QMessageBox.StandardButton.Yes:
            return
        deleted = 0; failed = 0
        for it in items:
            p = Path(it.text())
            try:
                p.unlink(missing_ok=True)
                deleted += 1
            except Exception:
                failed += 1
        # remove from UI/cache too
        self.remove_selected()
        QMessageBox.information(self, "Delete", f"☠️ Deleted {deleted}, ❌ failed {failed}.")



    def closeEvent(self, event):
        try:
            import json as _json
            files = [str(p) for p in self.files if Path(p).exists()]
            STATE_FILE.write_text(_json.dumps({"files": files, "prefs": self.prefs}, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        super().closeEvent(event)



    # ---- Drag & Drop ----
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        from pathlib import Path as _P
        paths = []
        for url in e.mimeData().urls():
            p = _P(url.toLocalFile())
            if p.is_dir():
                for f in p.rglob("*"):
                    if f.suffix.lower() in IMG_EXTS:
                        paths.append(f)
            elif p.suffix.lower() in IMG_EXTS and p.is_file():
                paths.append(p)
        if paths:
            self._add_paths(paths)
            self.status.showMessage(L["status_added"].format(n=len(paths)), 4000)


    def _run_with_progress(self, total, iterator, label: str):
        self._progress.setVisible(True)
        self._progress.setRange(0, total)
        i = 0
        for _ in iterator:
            i += 1
            self._progress.setValue(i)
            self.status.showMessage(f"{label}: {i}/{total}")
            QApplication.processEvents()
        self._progress.setVisible(False)
        self.status.clearMessage()



    def export_json_batch_selected(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "JSON", L["pick_one"]); return
        outdir = QFileDialog.getExistingDirectory(self, L["choose_json_dir"])
        if not outdir: return
        from pathlib import Path as _P
        outdir = _P(outdir)
        total = len(items); ok = 0; fail = 0
        def _work():
            nonlocal ok, fail
            for it in items:
                p = _P(it.text())
                try:
                    tags = self.meta_cache.get(str(p)) or read_all_metadata(p)
                    (outdir / (p.stem + ".frogglass.json")).write_text(
                        json.dumps(tags, ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                    ok += 1
                except Exception:
                    fail += 1
                yield None
        self._run_with_progress(total, _work(), "Export JSON")
        QMessageBox.information(self, "JSON", f"📝 Exported {ok}, ❌ failed {fail}.")

    def export_html_report_selected(self):
        items = self.listWidget.selectedItems()
        if not items:
            QMessageBox.information(self, "Report", L["pick_one"]); return
        save, _ = QFileDialog.getSaveFileName(self, "Save HTML report (selected)", L["report_filename"], "HTML (*.html)")
        if not save: return
        rows = []
        total = len(items)
        def _work():
            for it in items:
                p = Path(it.text())
                tags = self.meta_cache.get(str(p)) or read_all_metadata(p)
                gps = try_get_gps(tags)
                gps_str = f"{gps[0]:.6f}, {gps[1]:.6f}" if gps else ""
                rows.append(f"""
<section>
  <h2>{p.name}</h2>
  <p><b>Path:</b> {p}</p>
  <p><b>GPS:</b> {gps_str}</p>
  <details><summary>Tags</summary>
  <pre>{json.dumps(tags, ensure_ascii=False, indent=2)[:300000]}</pre>
  </details>
</section>
<hr/>""")
                yield None
        self._run_with_progress(total, _work(), "Report")
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>{L["html_title"]}</title>
<style>body{{font-family:system-ui;margin:24px}} pre{{white-space:pre-wrap;background:#111;color:#0f0;padding:12px;border-radius:10px}}</style>
</head><body>
{L["html_head"]}
{''.join(rows)}
</body></html>"""
        Path(save).write_text(html, encoding="utf-8")
        QMessageBox.information(self, "Report", L["report_ok"])
        if self.prefs.get("open_report_after_save", True):
            import webbrowser as _wb; _wb.open(str(Path(save).resolve()))


    def open_prefs(self):
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QCheckBox, QDialogButtonBox
        dlg = QDialog(self); dlg.setWindowTitle("Preferences")
        lay = QVBoxLayout(dlg)
        chk_inplace = QCheckBox("Default CLEAN as in-place (no copy)")
        chk_inplace.setChecked(self.prefs.get("inplace_clean_default", False))
        chk_verify = QCheckBox("Verify after NUKE (re-scan with ExifTool)")
        chk_verify.setChecked(self.prefs.get("verify_after_nuke", True))
        chk_openrep = QCheckBox("Open HTML report after saving")
        chk_openrep.setChecked(self.prefs.get("open_report_after_save", True))
        lay.addWidget(chk_inplace); lay.addWidget(chk_verify); lay.addWidget(chk_openrep)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        lay.addWidget(btns)
        def accept():
            self.prefs["inplace_clean_default"] = bool(chk_inplace.isChecked())
            self.prefs["verify_after_nuke"] = bool(chk_verify.isChecked())
            self.prefs["open_report_after_save"] = bool(chk_openrep.isChecked())
            dlg.accept()
        btns.accepted.connect(accept); btns.rejected.connect(dlg.reject)
        dlg.exec()

def main():


    app = QApplication(sys.argv)
    w = FrogGlassGUI()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
