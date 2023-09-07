import { z } from "zod";

import { type RandomGenerator } from "./types";

export class LcgRandom implements RandomGenerator {
  private generator: Generator<number>;

  constructor(
    modulus: number,
    multiplier: number,
    increment: number,
    seed: number
  ) {
    const argRecord = { modulus, multiplier, increment, seed };
    const generatorArgSchemaMap = new Map([
      ["modulus", z.number().gt(0)],
      ["multiplier", z.number().gt(0).lt(modulus)],
      ["increment", z.number().gte(0).lt(modulus)],
      ["seed", z.number().gte(0).lt(modulus)],
    ]);

    for (const [argKey, argValue] of Object.entries(argRecord)) {
      const schema = generatorArgSchemaMap.get(argKey) || z.number();
      schema.parse(argValue);
    }

    this.generator = this.lcg(modulus, multiplier, increment, seed);
  }

  public next(): number {
    return this.generator.next().value;
  }

  private *lcg(
    modulus: number,
    multiplier: number,
    increment: number,
    seed: number
  ): Generator<number, number, void> {
    const nextValue = (multiplier * seed + increment) % modulus;

    yield nextValue;

    yield* this.lcg(modulus, multiplier, increment, nextValue);

    return nextValue;
  }
}
