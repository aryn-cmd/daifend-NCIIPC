import sys
import os

def preview_xlsx(path, max_rows=10):
    try:
        import openpyxl
    except Exception:
        print("openpyxl not installed. If CSV fallback exists, list CSV files in output/.")
        for fname in os.listdir("output"):
            if fname.startswith("GC_PS_01_") and fname.endswith(".csv"):
                print("CSV:", os.path.join("output", fname))
        return 2
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    for ws in wb.worksheets:
        print(f"\nSheet: {ws.title} (showing up to {max_rows} rows)")
        rows = ws.iter_rows(values_only=True)
        header = next(rows, None)
        if header:
            print(" | ".join([str(h) for h in header]))
        count = 0
        for r in rows:
            print(" | ".join([str(c) if c is not None else "" for c in r]))
            count += 1
            if count >= max_rows:
                break
    return 0

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: preview_report.py <xlsx-path>")
        sys.exit(1)
    path = sys.argv[1]
    if not os.path.exists(path):
        print("File not found:", path)
        sys.exit(1)
    sys.exit(preview_xlsx(path))
