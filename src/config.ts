import type { UniversityBrand } from "./types/brand";

export const UNIVERSITY: UniversityBrand = {
  name: "XYZ University",
  shortName: "XYZ",
  tagline: "Blockchain Certificate Issuance & Verification",
  description: "Secure, tamper-proof student certificates issued and verified on the blockchain.",
  location: "India",
  established: "2026",
  logo: null,
};

export const DEFAULT_LOGO_SVG: string = `
  <svg width="80" height="80" viewBox="0 0 80 80" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="lg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#3b82f6"/>
        <stop offset="100%" stop-color="#a78bfa"/>
      </linearGradient>
    </defs>
    <rect x="4" y="4" width="72" height="72" rx="18" fill="url(#lg)"/>
    <path d="M40 18 L62 30 L40 42 L18 30 Z" fill="#fff"/>
    <path d="M26 38 v14 c0 5 6 8 14 8 s14 -3 14 -8 v-14" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round"/>
    <text x="40" y="68" text-anchor="middle" font-family="Segoe UI, sans-serif" font-size="13" font-weight="bold" fill="#fff">XYZ</text>
  </svg>
`;

export const LOGO_SVG: string = DEFAULT_LOGO_SVG;
