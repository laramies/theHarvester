# HarvestView design system

## Direction

Use the approved “Run desk” direction: a dark mineral navigation rail, warm neutral work surface, teal operational accent, amber warnings, and restrained red failures. The interface should feel like a field notebook crossed with a reliable control room-not a generic SaaS card grid.

## Typography

Use the local system stack only. Display and headings use a compact humanist sans stack; evidence values, IDs, timestamps, and status metadata use the system monospace stack. Body text stays at 16px on small screens and line length stays below 72 characters where prose appears.

## Layout

Desktop uses a fixed app header, a history rail, and one flexible evidence workbench. Result routes use a single table surface rather than nested cards. Tablet collapses secondary metadata. Mobile stacks history above evidence, preserves all actions, and keeps touch targets at least 44px.

## Color tokens

Use OKLCH tokens for background, surface, ink, muted text, line, teal accent, amber warning, red danger, and blue information. Light and dark themes must both meet WCAG AA contrast. Status always includes text or an icon as well as color.

## Interaction

Use native dialogs, buttons, inputs, details, and file controls. Motion is limited to short opacity/transform transitions for dialogs, notices, and selection; reduced-motion removes transforms and durations. Focus rings are never suppressed. Dynamic status changes use a polite live region.

## Tables and evidence

Use the locally served standalone Tabulator JavaScript build for sorting, filtering, selection, and pagination. Load only its pinned default table theme, with HarvestView's own stylesheet controlling the visual system. DNS status uses resolved, no-answer, disputed, and not-captured labels. Long values wrap or truncate with a title; they never break the viewport.

## CSS architecture

HarvestView uses its own `app.css` and native HTML controls. A general UI framework
would not make the interface better by itself; it would replace the existing Run
Desk visual language with framework defaults or require the same custom overrides
again.

| Option | Benefit | Cost for HarvestView | Decision |
| --- | --- | --- | --- |
| Custom CSS | Keeps the existing visual system, native controls, and zero-build workflow. | HarvestView owns its small reset and component rules. | Use. |
| Bootstrap | Mature components, utilities, and documentation. | No Bootstrap APIs are used; adding them would duplicate 232 KB of styles and make the interface more generic. | Remove. |
| Pico | Small class-light API and sensible semantic defaults. | Its global element styles compete with the existing native-control and theme rules. | Do not add. |
| Bulma | CSS-only component classes. | Requires a markup rewrite and adds a larger stylesheet without improving the evidence workflow. | Do not add. |
| Tailwind | Strong utility workflow and small compiled output when a build step is used. | Requires a markup rewrite and build pipeline; its browser CDN is development-only. | Do not add. |

Tabulator is the exception because it supplies table behavior HarvestView actually
uses. Its JavaScript and pinned default theme remain same-origin so local and
isolated-network use does not depend on a CDN. `app.css` owns the visual treatment
on top of that structural theme.

Primary references: [Bootstrap 5.3 installation](https://getbootstrap.com/docs/5.3/getting-started/introduction/),
[Tabulator 6.5 installation](https://tabulator.info/docs/6.5/install),
[Tabulator 6.5 themes](https://tabulator.info/docs/6.5/theme),
[Pico quick start](https://github.com/picocss/pico#quick-start),
[Bulma quick install](https://github.com/jgthms/bulma#quick-install), and
[Tailwind Play CDN guidance](https://tailwindcss.com/docs/installation/play-cdn).

## Voice

Use precise operator language: “Start enumeration,” “Request cancellation,” “Import result file,” and “No runs yet.” Errors state what failed and the next action. Avoid scan, session, job, and vague success/error labels where the glossary has a precise term.
