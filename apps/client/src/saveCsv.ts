import { File, Paths } from "expo-file-system";
import * as Sharing from "expo-sharing";
import { Share } from "react-native";
import { CSV, type FileType } from "./fileTypes";

/** Phones: writes the file to the app's cache and opens the share sheet (Save to Files, Mail, Drive, ...). */
export async function saveCsv(name: string, csv: string, title = "Export audit log", type: FileType = CSV): Promise<void> {
  const file = new File(Paths.cache, name);
  file.create({ overwrite: true });
  await file.write(csv);
  if (await Sharing.isAvailableAsync()) {
    await Sharing.shareAsync(file.uri, { mimeType: type.mime, UTI: type.uti, dialogTitle: title });
  } else {
    await Share.share({ title: name, message: csv });
  }
}
