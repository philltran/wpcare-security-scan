// Wordfence Intelligence feed normalizer.
//
// The impure fetch (downloading the free, no-auth bulk JSON feed) is kept thin and
// lives in the feed loader; this module is the PURE normalization that the matcher
// consumes — and is the part pinned by fixtures.
//
//   normalizeWordfenceFeed(rawFeed) -> { slug -> [ { affected_range, fixed_in,
//                                                    cvss, cve, title, url } ] }
//
// This slice normalizes the slice of the feed the matcher needs. The raw feed keys
// records by CVE id; each record's `software[]` lists affected plugins/themes by
// slug, each with one or more `affected_versions` ranges. We flatten that to a
// per-slug list of vuln records. See ADR-0003.

// A range's exclusive upper bound is the version the fix landed in: affected is
// strictly below `to_version` when `to_inclusive` is false. That is the field the
// matcher needs, so surface it as `fixed_in`.
function fixedInFromRange(range) {
  if (!range || typeof range !== 'object') return null;
  if (range.to_version && range.to_inclusive === false) return range.to_version;
  return null;
}

function firstReference(record) {
  const refs = Array.isArray(record.references) ? record.references : [];
  return refs.length ? refs[0] : null;
}

export function normalizeWordfenceFeed(rawFeed) {
  // A null-prototype map: slugs come from the external feed and some collide with
  // Object.prototype members (e.g. a slug "constructor" or "__proto__"). On a plain {}
  // that makes `bySlug[slug]` an inherited function and `(... ||= []).push` throws; a
  // null-proto object has no such members, so every slug — including "__proto__" — is a
  // safe own key. (Real-data bug surfaced on the live Wordfence feed.)
  const bySlug = Object.create(null);
  if (!rawFeed || typeof rawFeed !== 'object') return bySlug;

  for (const record of Object.values(rawFeed)) {
    if (!record || typeof record !== 'object') continue;
    const cve = record.cve || record.id || null;
    const title = record.title || null;
    const cvss = record.cvss && typeof record.cvss === 'object'
      ? record.cvss.score ?? null
      : null;
    const url = firstReference(record);

    const software = Array.isArray(record.software) ? record.software : [];
    for (const sw of software) {
      const slug = sw && sw.slug;
      if (!slug) continue;
      const ranges = sw.affected_versions && typeof sw.affected_versions === 'object'
        ? sw.affected_versions
        : {};

      for (const [label, range] of Object.entries(ranges)) {
        const rec = {
          affected_range: label,
          fixed_in: fixedInFromRange(range),
          cvss,
          cve,
          title,
          url,
        };
        (bySlug[slug] ||= []).push(rec);
      }
    }
  }

  return bySlug;
}
