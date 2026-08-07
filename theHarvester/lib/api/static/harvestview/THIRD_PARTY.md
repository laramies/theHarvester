# theHarvester frontend assets

HarvestView vendors the Tabulator JavaScript runtime and default theme so it has
no CDN or frontend build requirement.

- Tabulator 6.5.2: `tabulator.min.js` and `tabulator.min.css`, MIT license, https://tabulator.info/
  - Package: https://registry.npmjs.org/tabulator-tables/-/tabulator-tables-6.5.2.tgz
  - JavaScript package path: `package/dist/js/tabulator.min.js`
  - JavaScript SHA-256: `04802e757fa4189342c666d0f970a01d761c312798f31ffc664c24cbccc7ce3e`
  - JavaScript SRI: `sha256-BIAudX+kGJNCxmbQ+XCgHXYcMSeY8x/8Zkwky8zHzj4=`
  - CSS URL: https://unpkg.com/tabulator-tables@6.5.2/dist/css/tabulator.min.css
  - CSS SHA-256: `b55e204b2f968cecc4d3663d37858093b31dd22d20f01d76f590726ee18f7e1f`
  - CSS SRI: `sha384-7L13yWDATAJeK/mNTrYjb3Z8l08N1iGKbO9mSeSdlqR91llnpd0c4Y8wPznKlHCh`
- theHarvester logo SHA-256: `622b73540f8e85bbeb14281cba4cd54880db9f05b3f188fb8359cff84b7c6f2a`

Keep the adjacent Tabulator license when updating either asset. Review upstream
release notes, update both vendored assets and hashes together, and rerun the
browser suite before changing versions.
