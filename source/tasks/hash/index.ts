import inquirer from "inquirer";
import chalk from "chalk";

import { md5 } from "lib/crypto";
import { removeEdgeQuotes } from "lib/string";

type PromptResponse =
  | { messageSource: "string"; messageContent: string }
  | { messageSource: "file"; filePath: string };

const promptResponse = await inquirer.prompt<PromptResponse>([
  {
    type: "list",
    name: "messageSource",
    message: "Choose the message source:",
    choices: ["string", "file"],
  },
  {
    type: "string",
    name: "messageContent",
    message: "Message:",
    required: true,
    when: ({ messageSource }) => messageSource === "string",
  },
  {
    type: "string",
    name: "filePath",
    message: "File path:",
    required: true,
    when: ({ messageSource }) => messageSource === "file",
    filter: removeEdgeQuotes,
  },
]);

function logMessageDigest(messageDigest: string): void {
  console.log(`\n Hash: ${chalk.greenBright(messageDigest)}`);
}

if (promptResponse.messageSource === "string") {
  logMessageDigest(md5(promptResponse.messageContent));

  process.exit();
}

const file = Bun.file(promptResponse.filePath);

if (!(await file.exists())) {
  console.error(chalk.redBright("File does not exist"));

  process.exit(1);
}

const fileContent = await file.text();
logMessageDigest(md5(fileContent));
