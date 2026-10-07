/** One row in a student's subject list. */
export interface SubjectEntry {
  subject?: string;
  marks?: number | string | null;
  maxMarks?: number | string | null;
  grade?: string;
}

/** Aggregated marksheet stats produced by `computeStats`. */
export interface SubjectStats {
  total: number;
  max: number;
  pct: number;
  count: number;
  allPassed: boolean;
}

/** A result record as returned by `GET /api/results/verify`. */
export interface StudentResult {
  id: string;
  rollNumber: string;
  name?: string;
  department?: string;
  semester?: string;
  subjects?: SubjectEntry[];
  timestamp?: string | null;
}

/** Response of `POST /api/results/otp/request`. */
export interface OtpRequestResponse {
  success?: boolean;
  maskedMobile?: string;
  demoOtp?: string;
  note?: string;
  error?: string;
}

/** Response of `POST /api/results/otp/verify`. */
export interface OtpVerifyResponse {
  success?: boolean;
  resultToken?: string;
  error?: string;
}

/** Response of `POST /api/issues`. */
export interface IssueSubmitResponse {
  success?: boolean;
  error?: string;
}