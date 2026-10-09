/**
 * Lets only the newest of overlapping requests write its answer.
 *
 * `begin()` starts a request and returns a check that is true only while no later request has
 * begun. An earlier site's answer arriving last must not stay on screen under a later selection.
 */
export function latestOnly(): { begin(): () => boolean } {
  let latest = 0;
  return {
    begin() {
      const mine = ++latest;
      return () => mine === latest;
    },
  };
}
