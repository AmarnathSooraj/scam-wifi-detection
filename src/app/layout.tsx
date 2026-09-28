import type { Metadata } from "next";
import "@fontsource-variable/ibm-plex-sans";
import "@fontsource/ibm-plex-mono";
import "./globals.css";

export const metadata: Metadata = {
  title: "WiFiSentinel AI | Wireless Security Monitor",
  description: "AI-powered wireless security monitoring and access point risk analysis.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
