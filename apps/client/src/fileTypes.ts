/** What a saved file is, for the share sheet (`uti` on iOS) and the browser. */
export interface FileType {
  mime: string;
  uti: string;
}

export const CSV: FileType = { mime: "text/csv", uti: "public.comma-separated-values-text" };
export const MARKDOWN: FileType = { mime: "text/markdown", uti: "net.daringfireball.markdown" };
