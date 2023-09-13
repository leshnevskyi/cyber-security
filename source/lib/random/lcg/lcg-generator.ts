export function* lcgGenerator(
  modulus: number,
  multiplier: number,
  increment: number,
  seed: number
): Generator<number, number, void> {
  const nextValue = (multiplier * seed + increment) % modulus;

  yield nextValue;

  yield* lcgGenerator(modulus, multiplier, increment, nextValue);

  return nextValue;
}
