export interface RandomGenerator<TValue = number | bigint> {
  next: () => TValue;
}
