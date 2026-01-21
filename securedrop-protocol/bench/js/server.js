const express = require('express');
const serveStatic = require('serve-static');

async function startServer(rootDir) {
  const app = express();

  // COOP/COEP for crossOriginIsolated + precise timers + SAB
  app.use((req, res, next) => {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Timing-Allow-Origin', '*');
    next();
  });

  app.use(serveStatic(rootDir, {
    fallthrough: true,
    setHeaders(res, filePath) {
      if (filePath.endsWith('.wasm')) {
        res.setHeader('Content-Type', 'application/wasm');
      }
    },
  }));

  // 404
  app.use((req, res) => res.status(404).send('Not found'));

  return new Promise((resolve) => {
    const srv = app.listen(0, () => {
      const { port } = srv.address();
      resolve({ server: srv, port });
    });
  });
}

module.exports = {
  startServer,
};
