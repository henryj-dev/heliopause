// Shared by the renderer, which enforces it, and the manager, which relays to it. Its own file so the
// manager imports a number and nothing that touches the disk.

/** Largest edited file the render-diff preview accepts, in bytes. */
export const MAX_PREVIEW_BYTES = 1_000_000;
