/**
 * Shared brand / university identity types.
 *
 * Used by both the React frontend (config, App, AdminPage) and the Express
 * backend (server `/api/brand`), so they live in one place.
 */

/** The persisted brand record — exactly what `GET /api/brand` returns. */
export interface BrandRecord {
  name: string;
  shortName: string;
  logo: string | null;
}

/** The full frontend brand object: persisted fields + static page copy. */
export interface UniversityBrand extends BrandRecord {
  tagline: string;
  description: string;
  location: string;
  established: string;
}
