import { File, Paths } from "expo-file-system";
import * as Sharing from "expo-sharing";
import { Share } from "react-native";

/** Phones: writes the file to the app's cache and opens the share sheet (Save to Files, Mail, Drive, ...). */
export async function saveCsv(name: string, csv: string): Promise<void> {
  const file = new File(Paths.cache, name);
  file.create({ overwrite: true });
  await file.write(csv);
  if (await Sharing.isAvailableAsync()) {
    await Sharing.shareAsync(file.uri, { mimeType: "text/csv", UTI: "public.comma-separated-values-text", dialogTitle: "Export audit log" });
  } else {
    await Share.share({ title: name, message: csv });
  }
}
