/** A full certificate row as stored/returned by the backend. */
export interface CertificateRecord {
  hash: string;
  name: string;
  rollNumber?: string;
  course?: string;
  department?: string;
  year?: string;
  email?: string;
  ipfsHash?: string;
  txHash?: string;
  timestamp?: string | null;
}

/**
 * Response of `GET /api/verify/:hash`.
 * Success reveals only the hash + optional IPFS CID — never student personal data.
 */
export type VerifyCertificateResponse =
  | { valid: true; hash: string; ipfsHash?: string }
  | { valid: false };