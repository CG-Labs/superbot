import React from "react";

interface Props {
  url: string;
  title: string;
}

/** Web and Electron live view: voxl's page in an iframe, as in the embedded web app. */
export function ScreenFrame({ url, title }: Props) {
  return (
    <iframe
      src={url}
      title={title}
      allow="clipboard-read; clipboard-write"
      referrerPolicy="no-referrer"
      style={{ width: "100%", height: "100%", border: 0, display: "block", background: "#000" }}
    />
  );
}
