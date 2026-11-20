// Frame-buster (frame-ancestors can't be set from a <meta> CSP): refuse to run inside any frame.
if (window.top !== window.self) {
  document.documentElement.hidden = true;
  try { window.stop(); } catch (e) { /* */ }
  throw new Error('JARVIS refuses to run in a frame');
}
