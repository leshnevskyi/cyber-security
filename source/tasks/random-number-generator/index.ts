import { type BunFile } from "bun";
import path from "node:path";
import inquirer from "inquirer";
import chalk from "chalk";

import { LcgRandom } from "lib/random";

type LcgArgs = {
  modulus: number;
  multiplier: number;
  increment: number;
  seed: number;
};

type LogFileRecord = {
  timestamp: string;
  args: LcgArgs;
  result: number[];
};

type LogFileContent = LogFileRecord[];

const logFile = {
  name: "lcg.log.json",

  get path(): string {
    return path.join(import.meta.dir, this.name);
  },

  get ref(): BunFile {
    return Bun.file(this.path, { type: "application/json" });
  },

  get content(): Promise<LogFileContent> {
    return this.ref
      .exists()
      .then((fileExists) =>
        fileExists
          ? (this.ref.json() as Promise<LogFileContent>)
          : Promise.resolve([])
      );
  },
};

type PromptResponse = LcgArgs & {
  numberCount: number;
  shouldLog: boolean;
};

const { numberCount, modulus, multiplier, increment, seed, shouldLog } =
  await inquirer.prompt<PromptResponse>([
    {
      type: "number",
      name: "numberCount",
      message: "Number count:",
      default: 10,
    },
    {
      type: "number",
      name: "modulus",
      message: "Modulus:",
      default: 2 ** 18 - 1,
    },
    {
      type: "number",
      name: "multiplier",
      message: "Multiplier:",
      default: 5 ** 3,
    },
    { type: "number", name: "increment", message: "Increment:", default: 34 },
    { type: "number", name: "seed", message: "Seed:", default: 512 },
    {
      type: "confirm",
      name: "shouldLog",
      message: "Save numbers to file",
      default: true,
    },
  ]);

const randomGenerator = new LcgRandom(modulus, multiplier, increment, seed);

const randomNumbers = [...Array(numberCount)].map(() => randomGenerator.next());

console.log("\n");
console.group(chalk.bold(`Generated random ${numberCount} numbers:`));
randomNumbers.map((number) => console.log(chalk.cyan(number)));
console.groupEnd();

console.log("\n");
console.log(chalk.bold("Period:"), chalk.cyan(randomGenerator.period));

if (!shouldLog) process.exit();

Bun.write(
  logFile.path,
  JSON.stringify(
    [
      ...(await logFile.content),
      {
        timestamp: new Date().toISOString(),
        args: { modulus, multiplier, increment, seed },
        result: randomNumbers,
      },
    ],
    null,
    2
  )
);
