import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MailTrace AI — Email Threat Intelligence Platform",
  description: "AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform for security analysts and SOC teams.",
  keywords: ["email forensics", "phishing detection", "BEC detection", "cybersecurity", "email threat intelligence"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
