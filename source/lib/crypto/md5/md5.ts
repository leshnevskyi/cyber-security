import { FFIType, includeNative } from "lib/ffi";

type Md5HashFn = (message: string) => string;

const md5: Md5HashFn = (message: string) => {
  const { md5 } = includeNative("md5", {
    md5: {
      args: [FFIType.cstring],
      returns: FFIType.cstring,
    },
  });

  return md5(Buffer.from(message.concat("\0"), "utf8")).toString();
};

export default md5;
