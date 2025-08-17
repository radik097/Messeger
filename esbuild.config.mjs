import { build } from 'esbuild';
import { copyFileSync, mkdirSync } from 'fs';

const outdir = 'web';

await build({
  entryPoints: ['web/src/app.js'],
  bundle: true,
  outfile: `${outdir}/app.js`,
  sourcemap: false,
  minify: true,
});

// copy static files
mkdirSync(outdir, { recursive: true });
copyFileSync('web/src/index.html', `${outdir}/index.html`);
copyFileSync('web/src/styles.css', `${outdir}/styles.css`);
