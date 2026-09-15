const shapes = {
  linux: `<path d="M8 10c-1-7 1-9 4-9s5 2 4 9c4 3 5 8 2 10H6c-3-2-2-7 2-10Z" fill="currentColor" stroke="none"/><ellipse cx="12" cy="14" rx="4" ry="6" fill="white" stroke="none"/><ellipse cx="10.3" cy="6" rx="1" ry="1.5" fill="white" stroke="none"/><ellipse cx="13.7" cy="6" rx="1" ry="1.5" fill="white" stroke="none"/><path d="m9 8 3-1 3 1-3 2Z" fill="#d4a94e" stroke="none"/><path d="m7 18-4 3 6 1 1-3m7-1 4 3-6 1-1-3" fill="#d4a94e" stroke="none"/>`,
  android: `<path d="m7 4-2-3m12 3 2-3"/><path d="M4 9a8 8 0 0 1 16 0Zm0 2h16v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1Z" fill="currentColor" stroke="none"/><path d="M1 11v7m22-7v7M8 20v3m8-3v3" stroke-width="2.7"/><circle cx="8.5" cy="6" r=".8" fill="white" stroke="none"/><circle cx="15.5" cy="6" r=".8" fill="white" stroke="none"/>`,
  windows: `<path d="M2 4 11 2.8v8.4H2Zm11-.9L22 2v9.2h-9ZM2 13h9v8.2L2 20Zm11 0h9v9l-9-1Z" fill="currentColor" stroke="none"/>`,
};
Object.assign(shapes, {
  "overview": "<rect x=\"1.5\" y=\"1.5\" width=\"5\" height=\"5\" rx=\"1\" /><rect x=\"9.5\" y=\"1.5\" width=\"5\" height=\"5\" rx=\"1\" />\n      <rect x=\"1.5\" y=\"9.5\" width=\"5\" height=\"5\" rx=\"1\" /><rect x=\"9.5\" y=\"9.5\" width=\"5\" height=\"5\" rx=\"1\" />\n    ",
  "devices": "<rect x=\"2\" y=\"2\" width=\"12\" height=\"5\" rx=\"1.4\" /><rect x=\"2\" y=\"9\" width=\"12\" height=\"5\" rx=\"1.4\" />\n      <circle cx=\"4.5\" cy=\"4.5\" r=\".7\" /><circle cx=\"4.5\" cy=\"11.5\" r=\".7\" />\n      <path d=\"M7 4.5h4.5M7 11.5h4.5\" />\n    ",
  "topology": "<path d=\"M4.2 4.2L8 8m3.8-3.8L8 8m0 0v4.4\" /><circle cx=\"3\" cy=\"3\" r=\"1.8\" /><circle cx=\"13\" cy=\"3\" r=\"1.8\" /><circle cx=\"8\" cy=\"13.5\" r=\"1.8\" />\n    ",
  "services": "<rect x=\"2\" y=\"2\" width=\"12\" height=\"12\" rx=\"2\" /><path d=\"M5 5h6M5 8h6M5 11h4\" />\n    ",
  "routing": "<path d=\"M2 4h4.2C9 4 8.2 12 11 12h2.5M2 12h3.5C8.4 12 7.7 4 10.7 4h2.8\" /><path d=\"M11.5 2l2 2-2 2m0 4l2 2-2 2\" />\n    ",
  "releases": "<rect x=\"2\" y=\"3\" width=\"12\" height=\"10.5\" rx=\"2\" /><path d=\"M5 3V1.5h6V3M8 6v4m-2-2 2 2 2-2\" />\n    ",
  "events": "<circle cx=\"8\" cy=\"8\" r=\"6.2\" /><path d=\"M8 4.5V8l2.5 1.5\" />\n    ",
  "ssot": "<path d=\"M2 4h5m3 0h4M2 8h2m3 0h7M2 12h7m3 0h2\" /><circle cx=\"8.5\" cy=\"4\" r=\"1.5\" /><circle cx=\"5.5\" cy=\"8\" r=\"1.5\" /><circle cx=\"10.5\" cy=\"12\" r=\"1.5\" />\n    ",
  "download": "<path d=\"M8 2v8m-3-3 3 3 3-3M2.5 13.5h11\" />\n    "
});
export function icon(name, className = '') {
  return `<svg class="icon ${className}" viewBox="0 0 ${['linux','android','windows'].includes(name)?24:16} ${['linux','android','windows'].includes(name)?24:16}" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${shapes[name] || shapes.releases}</svg>`;
}
export const platforms = [{
  id: 'linux-server',
  label: 'Linux',
  icon: 'linux'
}, {
  id: 'android',
  label: 'Android',
  icon: 'android'
}, {
  id: 'windows-desktop',
  label: 'Windows',
  icon: 'windows'
}];
