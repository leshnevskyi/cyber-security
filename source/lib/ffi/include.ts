import { dlopen, suffix, type Narrow, type FFIFunction } from "bun:ffi";
import path from "node:path";

export function includeNative<
  TFunctions extends Record<string, Narrow<FFIFunction>>
>(packageName: string, functions: TFunctions) {
  const libFile = {
    prefix: "lib",
    suffix: suffix,
    name: packageName.replaceAll("-", "_"),

    get fullName(): string {
      return `${libFile.prefix}${libFile.name}.${libFile.suffix}`;
    },

    get absolutePath(): string {
      return path.join(
        "packages",
        packageName,
        "target",
        "release",
        libFile.fullName
      );
    },
  };

  const lib = dlopen(libFile.absolutePath, functions);

  return lib.symbols;
}
