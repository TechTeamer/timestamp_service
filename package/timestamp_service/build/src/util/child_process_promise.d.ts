import type { ExecOptions } from 'node:child_process';
interface Logger {
    info: (log: string, ...args: unknown[]) => unknown;
    error: (log: string, ...args: unknown[]) => unknown;
}
export declare function exec<ReturnType = string>(command: string, options?: {
    encoding?: 'buffer';
} & ExecOptions, logger?: Logger): Promise<ReturnType>;
export declare class ExecFileError extends Error {
    stdout?: string;
    stderr?: string;
}
export declare function execFile(command: string, args: string[], options?: {}): Promise<{
    stdout: string;
    stderr: string;
}>;
export {};
