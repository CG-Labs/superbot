import { CSV, type FileType } from "./fileTypes";

/** Web and Electron: a normal browser download. */
export async function saveCsv(name: string, csv: string, _title?: string, type: FileType = CSV): Promise<void> {
  const url = URL.createObjectURL(new Blob([csv], { type: `${type.mime};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoked later: some browsers start reading the blob only after click() returns.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
