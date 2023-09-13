import { z } from "zod";

import { lcgGenerator } from "./lcg-generator";
import { type RandomGenerator } from "./types";

import { includeNative, FFIType } from "lib/ffi";

type LcgPeriodGetter = (
  modulus: number | bigint,
  multiplier: number | bigint,
  increment: number | bigint,
  seed: number | bigint
) => bigint;

const lcgPeriod: LcgPeriodGetter = includeNative("lcg-period", {
  lcg_period: {
    args: [FFIType.u64, FFIType.u64, FFIType.u64, FFIType.u64],
    returns: FFIType.u64,
  },
}).lcg_period;

export class LcgRandom implements RandomGenerator {
  private generator: Generator<number>;

  constructor(
    public modulus: number,
    public multiplier: number,
    public increment: number,
    public seed: number
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

    this.generator = lcgGenerator(modulus, multiplier, increment, seed);
  }

  public next(): number {
    return this.generator.next().value;
  }

  public get period(): number {
    return Number(
      lcgPeriod(this.modulus, this.multiplier, this.increment, this.seed)
    );
  }
}
